package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.core.ticket.TicketTrackingPolicyTypes;
import org.apereo.cas.monitor.Monitorable;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisModulesOperations;
import org.apereo.cas.ticket.AuthenticationAwareTicket;
import org.apereo.cas.ticket.IdleExpirationPolicy;
import org.apereo.cas.ticket.ServiceAwareTicket;
import org.apereo.cas.ticket.ServiceTicket;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketCatalog;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.UniqueTicketIdGenerator;
import org.apereo.cas.ticket.registry.key.RedisKeyGenerator;
import org.apereo.cas.ticket.registry.key.RedisKeyGeneratorFactory;
import org.apereo.cas.ticket.registry.key.RedisPrincipalIdentifierCodec;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketIndexKeyGenerator;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketMutationFenceKeyGenerator;
import org.apereo.cas.ticket.registry.pub.RedisTicketRegistryMessagePublisher;
import org.apereo.cas.ticket.serialization.TicketSerializationManager;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.CompressionUtils;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.util.thread.Cleanable;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.hjson.JsonValue;
import org.hjson.Stringify;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.data.redis.core.convert.RedisData;
import org.springframework.data.redis.core.types.Expiration;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * Key-value ticket registry implementation that stores tickets in redis.
 *
 * @author Misagh Moayyed
 * @author Jerome Leleu
 * @since 5.1.0
 */
@Slf4j
@Monitorable
@Getter
public class RedisTicketRegistry extends AbstractTicketRegistry implements Cleanable, AutoCloseable {

    private static final String SEARCH_INDEX_NAME = RedisTicketDocument.class.getSimpleName() + "Index";

    private static final int PRINCIPAL_DELETE_CHUNK_SIZE = 100;

    private static final int WRITE_COMMAND_BASE_ARGUMENT_COUNT = 17;

    /**
     * Atomically writes a ticket hash, the Spring Data keyspace member, and
     * the complete principal-to-ticket index entry, and the legacy session
     * index entry. An update also removes the member from a previous
     * principal's indexes at the same linearization point.
     *
     * <p>This multi-key script follows the Redis ticket registry's existing
     * single-primary/Sentinel deployment contract. Redis Cluster would require
     * all keys to share a hash slot and is not supported by this key schema.</p>
     */
    private static final byte[] WRITE_TICKET_SCRIPT = """
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function expire_index(key, score_to_ms, expiry_offset_ms)
          local last = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
          if #last == 0 then
            redis.call('DEL', key)
          else
            redis.call('PEXPIREAT', key,
              math.floor((tonumber(last[2]) * score_to_ms) + expiry_offset_ms))
          end
        end
        local function refresh_index(key, now_score, score_to_ms, expiry_offset_ms)
          redis.call('ZREMRANGEBYSCORE', key, 0, now_score)
          expire_index(key, score_to_ms, expiry_offset_ms)
        end
        if redis.call('EXISTS', KEYS[3]) == 1 then
          return redis.error_reply('CAS registry-wide ticket deletion is in progress')
        end
        local ticket_type = keytype(KEYS[1])
        local keyspace_type = keytype(KEYS[2])
        if ticket_type ~= 'none' and ticket_type ~= 'hash' then
          return redis.error_reply('CAS principal ticket has wrong type')
        end
        if keyspace_type ~= 'none' and keyspace_type ~= 'set' then
          return redis.error_reply('CAS ticket keyspace has wrong type')
        end
        local expiration = tonumber(ARGV[1])
        local session_expiration = tonumber(ARGV[8])
        local session_mode = ARGV[9]
        local field_count = tonumber(ARGV[11])
        if not expiration or expiration <= 0 or not field_count or field_count < 1 then
          return redis.error_reply('CAS ticket write arguments are invalid')
        end
        if session_mode ~= 'N' and session_mode ~= 'A' and session_mode ~= 'M' then
          return redis.error_reply('CAS principal session index mode is invalid')
        end
        if session_mode ~= 'N' and
          (not session_expiration or session_expiration <= 0 or ARGV[7] == '') then
          return redis.error_reply('CAS principal session index arguments are invalid')
        end
        local mapped_principal
        local offset = 12
        for index = 1, field_count do
          if ARGV[offset] == ARGV[3] then
            mapped_principal = ARGV[offset + 1]
          end
          offset = offset + 2
        end
        if mapped_principal and mapped_principal ~= '' then
          local expected_key_count = session_mode == 'N' and 5 or 6
          if #KEYS ~= expected_key_count or
            KEYS[4] ~= ARGV[10] .. mapped_principal then
            return redis.error_reply('CAS principal mutation fence key is invalid')
          end
          if redis.call('EXISTS', KEYS[4]) == 1 then
            return redis.error_reply('CAS principal ticket mutation is fenced')
          end
          if KEYS[5] ~= ARGV[4] .. mapped_principal then
            return redis.error_reply('CAS principal ticket index key is invalid')
          end
          if session_mode ~= 'N' and KEYS[6] ~= ARGV[6] .. mapped_principal then
            return redis.error_reply('CAS principal session index key is invalid')
          end
        elseif #KEYS ~= 3 or session_mode ~= 'N' then
          return redis.error_reply('CAS principal ticket index is unexpected')
        end
        local old_principal
        if ticket_type == 'hash' then
          old_principal = redis.call('HGET', KEYS[1], ARGV[3])
        end
        local old_index
        if old_principal and old_principal ~= '' then
          local old_fence = ARGV[10] .. old_principal
          if redis.call('EXISTS', old_fence) == 1 then
            return redis.error_reply('CAS previous principal ticket mutation is fenced')
          end
          old_index = ARGV[4] .. old_principal
          local old_index_type = keytype(old_index)
          if old_index_type ~= 'none' and old_index_type ~= 'zset' then
            return redis.error_reply('CAS previous principal ticket index has wrong type')
          end
        end
        if #KEYS == 5 then
          local index_type = keytype(KEYS[5])
          if index_type ~= 'none' and index_type ~= 'zset' then
            return redis.error_reply('CAS principal ticket index has wrong type')
          end
        end
        if #KEYS == 6 then
          local index_type = keytype(KEYS[5])
          if index_type ~= 'none' and index_type ~= 'zset' then
            return redis.error_reply('CAS principal ticket index has wrong type')
          end
          local session_type = keytype(KEYS[6])
          if session_type ~= 'none' and session_type ~= 'zset' then
            return redis.error_reply('CAS principal session index has wrong type')
          end
        end
        local old_session
        if session_mode ~= 'N' and old_principal and old_principal ~= '' then
          old_session = ARGV[6] .. old_principal
          local old_session_type = keytype(old_session)
          if old_session_type ~= 'none' and old_session_type ~= 'zset' then
            return redis.error_reply('CAS previous principal session index has wrong type')
          end
        end
        local clock = redis.call('TIME')
        local now_ms = (tonumber(clock[1]) * 1000) +
          math.floor(tonumber(clock[2]) / 1000)
        local now_sec = math.floor(now_ms / 1000)
        local expired_session_cutoff = now_sec - 1
        if expiration <= now_ms then
          return redis.error_reply('CAS ticket expiration is not in the future')
        end
        if session_mode ~= 'N' and
          session_expiration ~= math.floor(expiration / 1000) then
          return redis.error_reply('CAS principal session expiration is inconsistent')
        end
        redis.call('DEL', KEYS[1])
        offset = 12
        for index = 1, field_count do
          redis.call('HSET', KEYS[1], ARGV[offset], ARGV[offset + 1])
          offset = offset + 2
        end
        redis.call('PEXPIREAT', KEYS[1], expiration)
        redis.call('SADD', KEYS[2], ARGV[2])
        if old_index and (#KEYS < 5 or old_index ~= KEYS[5]) then
          redis.call('ZREM', old_index, ARGV[5])
          refresh_index(old_index, now_ms, 1, 0)
        end
        if #KEYS >= 5 then
          redis.call('ZREMRANGEBYSCORE', KEYS[5], 0, now_ms)
          redis.call('ZADD', KEYS[5], expiration, ARGV[5])
          refresh_index(KEYS[5], now_ms, 1, 0)
        end
        if session_mode ~= 'N' then
          if old_session and old_session ~= KEYS[6] then
            redis.call('ZREM', old_session, ARGV[7])
            refresh_index(old_session, expired_session_cutoff, 1000, 999)
          end
          if session_mode == 'M' then
            redis.call('DEL', KEYS[6])
          else
            redis.call('ZREMRANGEBYSCORE', KEYS[6], 0, expired_session_cutoff)
          end
          redis.call('ZADD', KEYS[6], session_expiration, ARGV[7])
          expire_index(KEYS[6], 1000, 999)
        end
        return 1
        """.getBytes(StandardCharsets.UTF_8);

    /**
     * Atomically deletes one ticket and removes every authoritative index
     * member derived from the ticket hash. Missing tickets still clean stale
     * index and Spring Data keyspace members.
     */
    private static final byte[] DELETE_SINGLE_TICKET_SCRIPT = """
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function refresh_index(key, now_ms)
          redis.call('ZREMRANGEBYSCORE', key, 0, now_ms)
          local last = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
          if #last == 0 then
            redis.call('DEL', key)
          else
            redis.call('PEXPIREAT', key, math.floor(tonumber(last[2])))
          end
        end
        local ticket_type = keytype(KEYS[1])
        local keyspace_type = keytype(KEYS[2])
        if ticket_type ~= 'none' and ticket_type ~= 'hash' then
          return redis.error_reply('CAS principal ticket has wrong type')
        end
        if keyspace_type ~= 'none' and keyspace_type ~= 'set' then
          return redis.error_reply('CAS ticket keyspace has wrong type')
        end
        local principal = ARGV[2]
        if ticket_type == 'hash' then
          local stored_principal = redis.call('HGET', KEYS[1], ARGV[1])
          if stored_principal and stored_principal ~= '' then
            principal = stored_principal
          end
        end
        local actual_index
        local expected_index
        local actual_session
        local expected_session
        if principal and principal ~= '' then
          actual_index = ARGV[3] .. principal
          if keytype(actual_index) ~= 'none' and keytype(actual_index) ~= 'zset' then
            return redis.error_reply('CAS principal ticket index has wrong type')
          end
          if ARGV[7] == '1' then
            actual_session = ARGV[4] .. principal
            if keytype(actual_session) ~= 'none' and keytype(actual_session) ~= 'zset' then
              return redis.error_reply('CAS principal session index has wrong type')
            end
          end
        end
        if ARGV[2] and ARGV[2] ~= '' then
          expected_index = ARGV[3] .. ARGV[2]
          if keytype(expected_index) ~= 'none' and keytype(expected_index) ~= 'zset' then
            return redis.error_reply('CAS expected principal ticket index has wrong type')
          end
          if ARGV[7] == '1' then
            expected_session = ARGV[4] .. ARGV[2]
            if keytype(expected_session) ~= 'none' and keytype(expected_session) ~= 'zset' then
              return redis.error_reply('CAS expected principal session index has wrong type')
            end
          end
        end
        local clock = redis.call('TIME')
        local now_ms = (tonumber(clock[1]) * 1000) +
          math.floor(tonumber(clock[2]) / 1000)
        local deleted = redis.call('UNLINK', KEYS[1])
        redis.call('SREM', KEYS[2], ARGV[8])
        if actual_index then
          redis.call('ZREM', actual_index, ARGV[5])
          refresh_index(actual_index, now_ms)
        end
        if expected_index and expected_index ~= actual_index then
          redis.call('ZREM', expected_index, ARGV[5])
          refresh_index(expected_index, now_ms)
        end
        if actual_session then
          redis.call('ZREM', actual_session, ARGV[6])
        end
        if expected_session and expected_session ~= actual_session then
          redis.call('ZREM', expected_session, ARGV[6])
        end
        return deleted
        """.getBytes(StandardCharsets.UTF_8);

    /**
     * Atomically removes one bounded batch selected from a principal index.
     * The authoritative ticket principal is checked again before deletion so
     * a concurrently reassigned ticket is never removed for the old principal.
     */
    private static final byte[] DELETE_PRINCIPAL_TICKET_BATCH_SCRIPT = """
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function refresh_index(key, now_ms)
          redis.call('ZREMRANGEBYSCORE', key, 0, now_ms)
          local last = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
          if #last == 0 then
            redis.call('DEL', key)
          else
            redis.call('PEXPIREAT', key, math.floor(tonumber(last[2])))
          end
        end
        if redis.call('GET', KEYS[3]) ~= ARGV[3] or
          redis.call('EXISTS', KEYS[4]) == 1 then
          return redis.error_reply('CAS principal ticket deletion is not ready or is fenced')
        end
        local principal_index_type = keytype(KEYS[1])
        local session_index_type = keytype(KEYS[2])
        if principal_index_type ~= 'none' and principal_index_type ~= 'zset' then
          return redis.error_reply('CAS principal ticket index has wrong type')
        end
        if session_index_type ~= 'none' and session_index_type ~= 'zset' then
          return redis.error_reply('CAS principal session index has wrong type')
        end
        local ticket_count = (#KEYS - 4) / 2
        for index = 1, ticket_count do
          local ticket_offset = 3 + (index * 2)
          local keyspace_offset = ticket_offset + 1
          local ticket_type = keytype(KEYS[ticket_offset])
          local keyspace_type = keytype(KEYS[keyspace_offset])
          if ticket_type ~= 'none' and ticket_type ~= 'hash' then
            return redis.error_reply('CAS principal ticket has wrong type')
          end
          if keyspace_type ~= 'none' and keyspace_type ~= 'set' then
            return redis.error_reply('CAS ticket keyspace has wrong type')
          end
          if ticket_type == 'hash' then
            local ticket_principal = redis.call('HGET', KEYS[ticket_offset], ARGV[2])
            if not ticket_principal or ticket_principal == '' then
              return redis.error_reply('CAS principal ticket is missing its principal')
            end
          end
        end
        local deleted = 0
        for index = 1, ticket_count do
          local ticket_offset = 3 + (index * 2)
          local keyspace_offset = ticket_offset + 1
          local argument_offset = 4 + ((index - 1) * 4)
          local member = ARGV[argument_offset]
          local session_member = ARGV[argument_offset + 1]
          local document_id = ARGV[argument_offset + 2]
          local is_session = ARGV[argument_offset + 3]
          local ticket_type = keytype(KEYS[ticket_offset])
          local ticket_principal
          if ticket_type == 'hash' then
            ticket_principal = redis.call('HGET', KEYS[ticket_offset], ARGV[2])
          end
          redis.call('ZREM', KEYS[1], member)
          if is_session == '1' then
            redis.call('ZREM', KEYS[2], session_member)
          end
          if ticket_type == 'none' then
            redis.call('SREM', KEYS[keyspace_offset], document_id)
          elseif ticket_principal == ARGV[1] then
            deleted = deleted + redis.call('UNLINK', KEYS[ticket_offset])
            redis.call('SREM', KEYS[keyspace_offset], document_id)
          end
        end
        local clock = redis.call('TIME')
        local now_ms = (tonumber(clock[1]) * 1000) +
          math.floor(tonumber(clock[2]) / 1000)
        refresh_index(KEYS[1], now_ms)
        return deleted
        """.getBytes(StandardCharsets.UTF_8);

    /**
     * Selects one bounded principal-index page on the Redis primary. Using a
     * script prevents a replica read policy from observing a stale empty ZSET
     * and incorrectly completing account-scoped deletion.
     */
    private static final byte[] LOAD_PRINCIPAL_TICKET_BATCH_SCRIPT = """
        if redis.call('GET', KEYS[2]) ~= ARGV[2] or
          redis.call('EXISTS', KEYS[3]) == 1 then
          return redis.error_reply('CAS principal ticket deletion is not ready or is fenced')
        end
        local value = redis.call('TYPE', KEYS[1])
        local index_type = type(value) == 'table' and value.ok or value
        if index_type ~= 'none' and index_type ~= 'zset' then
          return redis.error_reply('CAS principal ticket index has wrong type')
        end
        local clock = redis.call('TIME')
        local now_ms = (tonumber(clock[1]) * 1000) +
          math.floor(tonumber(clock[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now_ms)
        return redis.call('ZRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)
        """.getBytes(StandardCharsets.UTF_8);

    private final CasRedisTemplates casRedisTemplates;

    private final ObjectProvider<Cache<String, Ticket>> ticketCache;

    private final ObjectProvider<RedisTicketRegistryMessagePublisher> messagePublisher;

    private final Optional<RedisModulesOperations> redisModulesOperations;

    private final RedisKeyGeneratorFactory redisKeyGeneratorFactory;

    private final CasConfigurationProperties casProperties;

    private final RedisKeyValueAdapter redisKeyValueAdapter;

    private final ObjectProvider<TicketRegistryWriteInterceptor> ticketRegistryWriteInterceptors;

    private final ObjectProvider<RedisTicketRegistryWriteExecutor> ticketRegistryWriteExecutors;

    @Getter(AccessLevel.PACKAGE)
    private final RedisPrincipalTicketIndex principalTicketIndex;

    public RedisTicketRegistry(final CipherExecutor cipherExecutor,
                               final TicketSerializationManager ticketSerializationManager,
                               final TicketCatalog ticketCatalog,
                               final ConfigurableApplicationContext applicationContext,
                               final CasRedisTemplates casRedisTemplates,
                               final ObjectProvider<Cache<String, Ticket>> ticketCache,
                               final ObjectProvider<RedisTicketRegistryMessagePublisher> messagePublisher,
                               final Optional<RedisModulesOperations> redisModulesOperations,
                               final RedisKeyGeneratorFactory redisKeyGeneratorFactory,
                               final RedisKeyValueAdapter redisKeyValueAdapter,
                               final CasConfigurationProperties casProperties) {
        super(cipherExecutor, ticketSerializationManager, ticketCatalog, applicationContext);
        this.casRedisTemplates = casRedisTemplates;
        this.ticketCache = ticketCache;
        this.messagePublisher = messagePublisher;
        this.redisModulesOperations = redisModulesOperations;
        this.redisKeyGeneratorFactory = redisKeyGeneratorFactory;
        this.casProperties = casProperties;
        this.redisKeyValueAdapter = redisKeyValueAdapter;
        this.ticketRegistryWriteInterceptors = applicationContext.getBeanProvider(TicketRegistryWriteInterceptor.class);
        this.ticketRegistryWriteExecutors = applicationContext.getBeanProvider(RedisTicketRegistryWriteExecutor.class);
        val redisCluster = casProperties.getTicket().getRegistry().getRedis().getCluster();
        if (redisCluster != null && !redisCluster.getNodes().isEmpty()) {
            throw new IllegalStateException(
                "Redis Cluster is not supported by the atomic ticket/principal index key schema; "
                + "use Redis single-primary or Sentinel");
        }
        this.principalTicketIndex = new RedisPrincipalTicketIndex(
            casRedisTemplates.getTicketsRedisTemplate(),
            casRedisTemplates.getSessionsRedisTemplate());
        createIndexesIfNecessary();
        val ticketGenerator = redisKeyGeneratorFactory
            .getRedisKeyGenerator(Ticket.class.getName())
            .orElseThrow();
        principalTicketIndex.rebuildIfNecessary(ticketGenerator.forEverything());
    }

    @Override
    public long deleteAll() {
        val leaseToken = principalTicketIndex.beginRegistryDelete();
        var completed = false;
        try {
            principalTicketIndex.deleteAll(leaseToken);
            val count = deleteAllKeys(
                redisKeyGeneratorFactory.getRedisKeyGenerator(Ticket.class.getName()).orElseThrow(),
                leaseToken);
            deleteTicketKeyspaces(leaseToken);
            deleteAllKeys(
                redisKeyGeneratorFactory.getRedisKeyGenerator(Principal.class.getName()).orElseThrow(),
                leaseToken);
            clean();
            principalTicketIndex.completeRegistryDelete(leaseToken);
            completed = true;
            return count;
        } finally {
            if (!completed) {
                principalTicketIndex.abortRegistryDelete(leaseToken);
            }
        }
    }

    private long deleteAllKeys(final RedisKeyGenerator redisKeyGenerator,
                               final String leaseToken) {
        val keyPattern = redisKeyGenerator.isTicketKeyGenerator()
            ? redisKeyGenerator.forEverything()
            : redisKeyGenerator.getNamespace() + ":*";
        val deleted = principalTicketIndex.deleteKeysOnPrimary(
            casRedisTemplates.getTicketsRedisTemplate(), keyPattern, leaseToken);
        return redisKeyGenerator.isTicketKeyGenerator() ? deleted : 0;
    }

    private void deleteTicketKeyspaces(final String leaseToken) {
        val keyspaces = redisKeyGeneratorFactory.getRedisKeyGenerators()
            .stream()
            .filter(RedisKeyGenerator::isTicketKeyGenerator)
            .map(RedisKeyGenerator::getKeyspace)
            .filter(StringUtils::isNotBlank)
            .collect(Collectors.toUnmodifiableSet());
        principalTicketIndex.deleteExactKeysOnPrimary(
            casRedisTemplates.getTicketsRedisTemplate(), keyspaces, leaseToken);
    }

    @Override
    public long deleteSingleTicket(final Ticket ticket) {
        val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(ticket.getPrefix()).orElseThrow();
        val digestedId = digestIdentifier(ticket.getId());
        val redisTicketsKey = redisKeyGenerator.forPrefixAndId(ticket.getPrefix(), digestedId);
        val principalGenerator = redisKeyGeneratorFactory
            .getRedisKeyGenerator(Principal.class.getName())
            .orElseThrow();
        val expectedPrincipal = encodePrincipalIdentifier(getPrincipalIdFrom(ticket));
        val keysAndArguments = new ArrayList<byte[]>(10);
        keysAndArguments.add(redisTicketsKey.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(redisKeyGenerator.getKeyspace().getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(RedisTicketDocument.FIELD_NAME_PRINCIPAL.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(expectedPrincipal.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(RedisPrincipalTicketIndexKeyGenerator.prefix().getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add((principalGenerator.getNamespace() + ':').getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(redisTicketsKey.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(serializeSessionIndexMember(digestedId));
        keysAndArguments.add((ticket instanceof TicketGrantingTicket ? "1" : "0")
            .getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(digestedId.getBytes(StandardCharsets.UTF_8));
        val result = casRedisTemplates.getTicketsRedisTemplate().execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                DELETE_SINGLE_TICKET_SCRIPT,
                ReturnType.INTEGER,
                2,
                keysAndArguments.toArray(byte[][]::new)));
        val count = requireDeleteScriptResult(result, 1, "single-ticket delete");

        ticketCache.ifAvailable(cache -> cache.invalidate(redisKeyGenerator.rawKey(redisTicketsKey)));
        messagePublisher.ifAvailable(publisher -> publisher.delete(ticket));
        return count;
    }

    @Override
    protected List<? extends Ticket> addTickets(final Stream<? extends Ticket> toSave) {
        /*
         * Each EVAL result must be observed before cache and message callbacks
         * run. Queueing addSingleTicket in a pipeline would execute those
         * callbacks before Redis can report a principal/global fence rejection.
         */
        return toSave.map(this::addSingleTicket).toList();
    }

    @Override
    protected Ticket addSingleTicket(final Ticket ticket) {
        LOGGER.debug("Adding ticket [{}]", ticket);
        addOrUpdateTicket(ticket, TicketRegistryWriteInterceptor.Operation.ADD);
        return ticket;
    }

    @Override
    protected Ticket addSingleTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) {
        LOGGER.debug("Adding ticket [{}] with explicit issuance context", ticket);
        addOrUpdateTicket(ticket, TicketRegistryWriteInterceptor.Operation.ADD, context);
        return ticket;
    }

    @Override
    protected Ticket updateSingleTicket(final Ticket ticket) {
        if (ticket != null) {
            LOGGER.debug("Updating ticket [{}]", ticket);
            addOrUpdateTicket(ticket, TicketRegistryWriteInterceptor.Operation.UPDATE);
        }
        return ticket;
    }

    @Override
    protected Ticket updateSingleTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) {
        if (ticket != null) {
            LOGGER.debug("Updating ticket [{}] with explicit issuance context", ticket);
            addOrUpdateTicket(ticket, TicketRegistryWriteInterceptor.Operation.UPDATE, context);
        }
        return ticket;
    }

    @Override
    protected Ticket getSingleTicket(final String ticketId, final Predicate<Ticket> predicate) {
        return readSingleTicket(ticketId, predicate, true);
    }

    @Override
    protected Ticket getSingleTicketFromSource(
        final String ticketId,
        final Predicate<Ticket> predicate) {
        return readSingleTicket(ticketId, predicate, false);
    }

    private Ticket readSingleTicket(
        final String ticketId,
        final Predicate<Ticket> predicate,
        final boolean nearCacheAllowed) {
        return FunctionUtils.doAndHandle(() -> {
            val ticketPrefix = StringUtils.substring(ticketId, 0, ticketId.indexOf(UniqueTicketIdGenerator.SEPARATOR));
            val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(ticketPrefix).orElseThrow();
            val redisTicketsKey = redisKeyGenerator.forPrefixAndId(ticketPrefix, digestIdentifier(ticketId));
            return getTicketFromRedis(
                predicate, redisTicketsKey, redisKeyGenerator, nearCacheAllowed);
        });
    }

    @Override
    protected Collection<? extends Ticket> getAllTickets() {
        try (val ticketsStream = streamTickets(TicketRegistryStreamCriteria.builder().build())) {
            return ticketsStream.collect(Collectors.toSet());
        }
    }

    @Override
    protected Stream<? extends Ticket> streamTickets(final TicketRegistryStreamCriteria criteria) {
        return fetchKeysForTickets()
            .skip(criteria.getFrom())
            .limit(criteria.getCount())
            .map(redisKey -> {
                val compositeKey = RedisKeyGenerator.parse(redisKey);
                val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(compositeKey.getPrefix()).orElseThrow();
                val keyspace = redisKeyGenerator.getKeyspace();
                val entryId = redisKeyGenerator.rawKey(redisKey);
                val document = redisKeyValueAdapter.get(entryId, keyspace, RedisTicketDocument.class);
                if (document == null) {
                    LOGGER.warn("Redis ticket key [{}] could not be mapped; preserving it for "
                        + "fail-closed recovery instead of bypassing authoritative index cleanup", redisKey);
                    return null;
                }
                return document;
            })
            .filter(Objects::nonNull)
            .map(this::deserializeTicket)
            .map(this::decodeTicket)
            .filter(Objects::nonNull)
            .peek(ticket -> {
                if (!ticket.isExpired()) {
                    val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(ticket.getPrefix()).orElseThrow();
                    val redisTicketsKey = redisKeyGenerator.forPrefixAndId(ticket.getPrefix(), digestIdentifier(ticket.getId()));
                    ticketCache.ifAvailable(cache -> cache.put(redisKeyGenerator.rawKey(redisTicketsKey), ticket));
                }
            });
    }


    @Override
    protected Stream<? extends Ticket> streamTicketsFor(final Service service) {
        return redisModulesOperations
            .stream()
            .map(command -> {
                val originalUrl = URI.create(service.getOriginalUrl());
                val host = String.format("%s?//%s", originalUrl.getScheme(), originalUrl.getHost());
                val query = String.format("@%s:\"%s\"", RedisTicketDocument.FIELD_NAME_SERVICE, host);
                LOGGER.debug("Executing search query [{}]", query);
                return command.search(SEARCH_INDEX_NAME, query)
                    .map(RedisTicketDocument::from)
                    .filter(document -> StringUtils.isNotBlank(document.json()))
                    .map(redisDoc -> {
                        val ticket = deserializeTicket(redisDoc);
                        return decodeTicket(ticket);
                    })
                    .filter(Objects::nonNull)
                    .filter(ticket -> !ticket.isExpired());
            })
            .findFirst()
            .orElseGet(() -> (Stream<Ticket>) super.streamTicketsFor(service));
    }
    
    @Override
    protected Stream<? extends Ticket> streamSessionsFor(final String principalId) {
        return redisKeyGeneratorFactory.getRedisKeyGenerator(Principal.class.getName())
            .map(generator -> {
                if (StringUtils.isBlank(principalId)) {
                    return Stream.<Ticket>empty();
                }
                val seenTicketIds = new HashSet<String>();
                return principalSessionIdentifiers(generator, principalId)
                    .stream()
                    .flatMap(mappedPrincipal -> streamSessionsForMappedPrincipal(
                        generator, mappedPrincipal))
                    .filter(ticket -> seenTicketIds.add(ticket.getId()));
            })
            .orElseGet(Stream::empty);
    }

    private Stream<Ticket> streamSessionsForMappedPrincipal(
        final RedisKeyGenerator principalKeyGenerator,
        final String mappedPrincipal) {
        val redisPrincipalKey = principalKeyGenerator.forId(mappedPrincipal);
        val options = ScanOptions.scanOptions().count(1000).build();
        val cursor = casRedisTemplates.getSessionsRedisTemplate()
            .boundZSetOps(redisPrincipalKey).scan(options);
        val spliterator = Spliterators.spliteratorUnknownSize(
            cursor, Spliterator.ORDERED | Spliterator.NONNULL);
        return StreamSupport.stream(spliterator, false)
            .onClose(cursor::close)
            .map(ZSetOperations.TypedTuple::getValue)
            .filter(Objects::nonNull)
            .map(ticketId -> {
                val redisKeyGenerator = redisKeyGeneratorFactory
                    .getRedisKeyGenerator(TicketGrantingTicket.PREFIX)
                    .orElseThrow();
                val redisTicketsKey = redisKeyGenerator.forPrefixAndId(
                    redisKeyGenerator.getPrefix(), ticketId);
                return getTicketFromRedis(
                    ticket -> !ticket.isExpired(), redisTicketsKey, redisKeyGenerator);
            })
            .filter(Objects::nonNull)
            .map(this::decodeTicket)
            .filter(Objects::nonNull)
            .filter(ticket -> !ticket.isExpired());
    }

    private List<String> principalSessionIdentifiers(
        final RedisKeyGenerator principalKeyGenerator,
        final String rawPrincipal) {
        val identifiers = principalAuthorityIdentifiers(rawPrincipal);
        if (identifiers.size() > 1
            && casProperties.getTicket().getTgt().getCore().getServiceTrackingPolicy()
                == TicketTrackingPolicyTypes.MOST_RECENT) {
            val canonicalSessionKey = principalKeyGenerator.forId(identifiers.getFirst());
            if (Boolean.TRUE.equals(casRedisTemplates.getSessionsRedisTemplate()
                .hasKey(canonicalSessionKey))) {
                return List.of(identifiers.getFirst());
            }
        }
        return identifiers;
    }

    @Override
    @SuppressWarnings("ReferenceEquality")
    public long deleteTicketsFor(final String principalId) {
        principalTicketIndex.requireReady();
        var deleted = 0L;
        Throwable publicationFailure = null;
        val targets = principalAuthorityIdentifiers(principalId);
        if (targets.isEmpty()) {
            return 0;
        }
        val principalGenerator = redisKeyGeneratorFactory
            .getRedisKeyGenerator(Principal.class.getName())
            .orElseThrow();
        val sessionTicketPrefixes = ticketCatalog
            .findTicketImplementations(TicketGrantingTicket.class)
            .stream()
            .map(definition -> definition.getPrefix())
            .collect(Collectors.toUnmodifiableSet());
        for (val target : targets) {
            val principalIndexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(target);
            val sessionIndexKey = principalGenerator.forId(target);
            while (true) {
                val members = loadPrincipalTicketBatch(principalIndexKey);
                if (members.isEmpty()) {
                    break;
                }
                val toDelete = members
                    .stream()
                    .map(redisKey -> {
                        val compositeKey = RedisKeyGenerator.parse(redisKey);
                        val redisKeyGenerator = redisKeyGeneratorFactory
                            .getRedisKeyGenerator(compositeKey.getPrefix())
                            .orElseThrow();
                        val cacheKey = redisKeyGenerator.rawKey(redisKey);
                        return new RedisTicketToDelete(
                            redisKey,
                            cacheKey,
                            compositeKey.getId(),
                            redisKeyGenerator.getKeyspace(),
                            compositeKey.getId(),
                            sessionTicketPrefixes.contains(compositeKey.getPrefix()));
                    })
                    .toList();
                deleted += deletePrincipalTicketBatch(
                    target, principalIndexKey, sessionIndexKey, toDelete);
                ticketCache.ifAvailable(cache -> toDelete.forEach(
                    ticketToDelete -> cache.invalidate(ticketToDelete.cacheKey())));
                val publisher = messagePublisher.getIfAvailable();
                if (publisher != null) {
                    for (val ticketToDelete : toDelete) {
                        try {
                            publisher.deleteByKey(ticketToDelete.redisKey());
                        } catch (final Throwable cause) {
                            if (cause instanceof final Error error) {
                                throw error;
                            }
                            if (publicationFailure == null) {
                                publicationFailure = cause;
                            } else if (cause != publicationFailure) {
                                publicationFailure.addSuppressed(cause);
                            }
                        }
                    }
                }
            }
        }
        if (publicationFailure != null) {
            throw rethrowUnchecked(publicationFailure);
        }
        return deleted;
    }

    List<String> loadPrincipalTicketBatch(final String principalIndexKey) {
        val result = casRedisTemplates.getSessionsRedisTemplate().execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                LOAD_PRINCIPAL_TICKET_BATCH_SCRIPT,
                ReturnType.MULTI,
                3,
                principalIndexKey.getBytes(StandardCharsets.UTF_8),
                RedisPrincipalTicketIndexKeyGenerator.READY_KEY.getBytes(StandardCharsets.UTF_8),
                RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY.getBytes(StandardCharsets.UTF_8),
                Integer.toString(PRINCIPAL_DELETE_CHUNK_SIZE).getBytes(StandardCharsets.UTF_8),
                RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION.getBytes(StandardCharsets.UTF_8)));
        if (result == null) {
            throw new IllegalStateException("Redis principal ticket index returned no batch result");
        }
        return result.stream()
            .map(value -> value instanceof final byte[] bytes
                ? new String(bytes, StandardCharsets.UTF_8)
                : Objects.toString(value, StringUtils.EMPTY))
            .filter(StringUtils::isNotBlank)
            .toList();
    }

    long deletePrincipalTicketBatch(final String target,
                                    final String principalIndexKey,
                                    final String sessionIndexKey,
                                    final List<RedisTicketToDelete> ticketChunk) {
        val keysAndArguments = new ArrayList<byte[]>((ticketChunk.size() * 6) + 7);
        keysAndArguments.add(principalIndexKey.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(sessionIndexKey.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(RedisPrincipalTicketIndexKeyGenerator.READY_KEY.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(
            RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY.getBytes(StandardCharsets.UTF_8));
        ticketChunk.forEach(ticket -> {
            keysAndArguments.add(ticket.redisKey().getBytes(StandardCharsets.UTF_8));
            keysAndArguments.add(ticket.keyspace().getBytes(StandardCharsets.UTF_8));
        });
        keysAndArguments.add(target.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(RedisTicketDocument.FIELD_NAME_PRINCIPAL.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION.getBytes(StandardCharsets.UTF_8));
        ticketChunk.forEach(ticket -> {
            keysAndArguments.add(ticket.redisKey().getBytes(StandardCharsets.UTF_8));
            keysAndArguments.add(serializeSessionIndexMember(ticket.sessionIndexMember()));
            keysAndArguments.add(ticket.documentId().getBytes(StandardCharsets.UTF_8));
            keysAndArguments.add((ticket.sessionTicket() ? "1" : "0").getBytes(StandardCharsets.UTF_8));
        });

        val result = casRedisTemplates.getTicketsRedisTemplate().execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                DELETE_PRINCIPAL_TICKET_BATCH_SCRIPT,
                ReturnType.INTEGER,
                (ticketChunk.size() * 2) + 4,
                keysAndArguments.toArray(byte[][]::new)));
        return requireDeleteScriptResult(
            result, ticketChunk.size(), "principal-ticket batch delete");
    }

    static long requireDeleteScriptResult(final @Nullable Long result,
                                          final long maximum,
                                          final String operation) {
        if (result == null) {
            throw new IllegalStateException("Redis %s returned no result".formatted(operation));
        }
        if (result < 0 || result > maximum) {
            throw new IllegalStateException(
                "Redis %s returned an invalid result [%d]".formatted(operation, result));
        }
        return result;
    }

    private String encodePrincipalIdentifier(final String rawPrincipal) {
        return rawPrincipal == null || rawPrincipal.isEmpty()
            ? rawPrincipal
            : RedisPrincipalIdentifierCodec.encode(rawPrincipal);
    }

    private List<String> principalAuthorityIdentifiers(final String rawPrincipal) {
        if (StringUtils.isBlank(rawPrincipal)) {
            return List.of();
        }
        val identifiers = new LinkedHashSet<String>();
        identifiers.add(RedisPrincipalIdentifierCodec.encode(rawPrincipal));
        val legacyIdentifier = digestIdentifier(rawPrincipal);
        if (StringUtils.isNotBlank(legacyIdentifier)) {
            identifiers.add(legacyIdentifier);
        }
        return List.copyOf(identifiers);
    }

    private byte[] serializeSessionIndexMember(final String member) {
        val serializer = (RedisSerializer<String>)
            casRedisTemplates.getSessionsRedisTemplate().getValueSerializer();
        return Objects.requireNonNull(serializer.serialize(member));
    }

    @Override
    public long countSessionsFor(final String principalId) {
        return redisKeyGeneratorFactory.getRedisKeyGenerator(Principal.class.getName())
            .map(generator -> {
                if (StringUtils.isBlank(principalId)) {
                    return 0L;
                }
                val now = Instant.now(Clock.systemUTC());
                val expiredSessionCutoff = now.getEpochSecond() - 1;
                val members = new HashSet<String>();
                principalSessionIdentifiers(generator, principalId).forEach(mappedPrincipal -> {
                    val redisPrincipalKey = generator.forId(mappedPrincipal);
                    val ops = casRedisTemplates.getSessionsRedisTemplate()
                        .boundZSetOps(redisPrincipalKey);
                    ops.removeRangeByScore(0, Long.valueOf(expiredSessionCutoff).doubleValue());
                    val current = ops.range(0, -1);
                    if (current != null) {
                        members.addAll(current);
                    }
                });
                return (long) members.size();
            })
            .filter(Objects::nonNull)
            .orElse(0L);
    }

    @Override
    public long sessionCount() {
        val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(TicketGrantingTicket.PREFIX).orElseThrow();
        val redisTicketsKey = redisKeyGenerator.forPrefixAndId(redisKeyGenerator.getPrefix(), "*");

        val options = ScanOptions.scanOptions().match(redisTicketsKey).build();
        try (val result = casRedisTemplates.getTicketsRedisTemplate().scan(options)) {
            return result.stream().parallel().count();
        }
    }

    @Override
    public long serviceTicketCount() {
        val redisTicketsKey = redisKeyGeneratorFactory.getRedisKeyGenerator(ServiceTicket.PREFIX)
            .orElseThrow().forPrefixAndId(ServiceTicket.PREFIX, "*");
        val options = ScanOptions.scanOptions().match(redisTicketsKey).build();
        try (val result = casRedisTemplates.getTicketsRedisTemplate().scan(options)) {
            return result.stream().parallel().count();
        }
    }

    @Override
    protected Stream<? extends Ticket> streamSessionsWithAttributes(final Map<String, List<Object>> queryAttributes) {
        return redisModulesOperations
            .stream()
            .map(command -> {
                val criteria = new ArrayList<String>();
                queryAttributes.forEach((key, value) -> value.forEach(queryValue -> {
                    val escapedValue = isCipherExecutorEnabled()
                        ? digestIdentifier(queryValue.toString())
                        : Strings.CI.replace(queryValue.toString(), "-", "\\-");
                    criteria.add(String.format("(%s%s*%s)", digestIdentifier(key), isCipherExecutorEnabled() ? " " : "_", escapedValue));
                }));
                val query = String.format("(%s) @%s:%s", String.join("|", criteria),
                    RedisTicketDocument.FIELD_NAME_PREFIX, TicketGrantingTicket.PREFIX);
                LOGGER.debug("Executing search query [{}]", query);
                return command.search(SEARCH_INDEX_NAME, query)
                    .map(RedisTicketDocument::from)
                    .filter(document -> StringUtils.isNotBlank(document.json()))
                    .map(redisDoc -> {
                        val ticket = deserializeTicket(redisDoc);
                        return decodeTicket(ticket);
                    })
                    .filter(ticket -> !ticket.isExpired());
            })
            .findFirst()
            .orElseGet(() -> (Stream<Ticket>) super.streamSessionsWithAttributes(queryAttributes));
    }

    @Override
    public long countTicketsFor(final Service service) {
        return redisModulesOperations
            .stream()
            .map(command -> {
                val originalUrl = URI.create(service.getOriginalUrl());
                val host = String.format("%s?//%s", originalUrl.getScheme(), originalUrl.getHost());
                val query = String.format("@%s:\"%s\"", RedisTicketDocument.FIELD_NAME_SERVICE, host);
                return command.search(SEARCH_INDEX_NAME, query)
                    .map(RedisTicketDocument::from)
                    .filter(document -> StringUtils.isNotBlank(document.json()))
                    .map(redisDoc -> {
                        val ticket = deserializeTicket(redisDoc);
                        return decodeTicket(ticket);
                    })
                    .filter(Objects::nonNull)
                    .filter(ticket -> !ticket.isExpired())
                    .count();
            })
            .findFirst()
            .orElseGet(() -> super.countTicketsFor(service));
    }

    @Override
    public long countTickets() {
        val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(Ticket.class.getName()).orElseThrow();
        val redisTicketsKey = redisKeyGenerator.forEverything();
        return casRedisTemplates.getTicketsRedisTemplate().count(redisTicketsKey);
    }

    @Override
    protected List<? extends Serializable> queryTickets(final TicketRegistryQueryCriteria queryCriteria) {
        val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(queryCriteria.getType()).orElseThrow();
        val redisTicketsKey = StringUtils.isNotBlank(queryCriteria.getId())
            ? redisKeyGenerator.forPrefixAndId(queryCriteria.getType(), digestIdentifier(queryCriteria.getId()))
            : redisKeyGenerator.forPrefixAndId(queryCriteria.getType(), "*");

        if (queryCriteria.isDecode()) {
            try (val scanResults = casRedisTemplates.getTicketsRedisTemplate().scan(redisTicketsKey, queryCriteria.getCount())) {
                return scanResults
                    .parallel()
                    .map(key -> {
                        val rawKey = redisKeyGenerator.rawKey(key);
                        val cachedTicket = ticketCache.stream()
                            .map(cache -> cache.getIfPresent(rawKey))
                            .filter(Objects::nonNull)
                            .findFirst();
                        return cachedTicket.orElseGet(() -> {
                            val keyspace = redisKeyGenerator.getKeyspace();
                            val redisDocument = redisKeyValueAdapter.get(rawKey, keyspace, RedisTicketDocument.class);
                            return Stream.ofNullable(redisDocument)
                                .filter(Objects::nonNull)
                                .map(this::deserializeTicket)
                                .filter(Objects::nonNull)
                                .findFirst()
                                .orElse(null);
                        });
                    })
                    .filter(Objects::nonNull)
                    .map(this::decodeTicket)
                    .filter(ticket -> StringUtils.isBlank(queryCriteria.getPrincipal())
                        || (ticket instanceof final AuthenticationAwareTicket aat
                        && Strings.CI.equals(queryCriteria.getPrincipal(), aat.getAuthentication().getPrincipal().getId())))
                    .filter(ticket -> !ticket.isExpired())
                    .peek(ticket -> {
                        val cacheKey = redisKeyGenerator.forPrefixAndId(ticket.getPrefix(), digestIdentifier(ticket.getId()));
                        ticketCache.ifAvailable(c -> c.put(redisKeyGenerator.rawKey(cacheKey), ticket));
                    })
                    .collect(Collectors.toList());
            }
        }
        val keys = fetchKeysForTickets(redisTicketsKey);
        return (queryCriteria.getCount() > 0 ? keys.limit(queryCriteria.getCount()) : keys).collect(Collectors.toList());
    }

    @Override
    public void clean() {
        ticketCache.ifAvailable(Cache::invalidateAll);
        messagePublisher.ifAvailable(RedisTicketRegistryMessagePublisher::deleteAll);
    }

    @Override
    public void close() {
        principalTicketIndex.close();
    }

    private Stream<String> fetchKeysForTickets() {
        val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(Ticket.class.getName()).orElseThrow();
        val redisKey = redisKeyGenerator.forEverything();
        return fetchKeysForTickets(redisKey);
    }

    private Stream<String> fetchKeysForTickets(final String keyPattern) {
        LOGGER.debug("Loading keys for pattern [{}]", keyPattern);
        return casRedisTemplates.getTicketsRedisTemplate().scan(keyPattern);
    }

    protected RedisTicketDocument buildTicketAsDocument(final Ticket ticket) {
        return FunctionUtils.doUnchecked(() -> {
            if (casProperties.getSlo().isDisabled() && ticket instanceof final TicketGrantingTicket tgt) {
                tgt.removeAllServices();
            }
            val encTicket = encodeTicket(ticket);
            val json = serializeTicket(encTicket);
            FunctionUtils.throwIf(StringUtils.isBlank(json),
                () -> new IllegalArgumentException("Ticket %s cannot be serialized to JSON".formatted(ticket.getId())));

            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Serialized ticket into a JSON document as\n [{}]",
                    JsonValue.readJSON(json).toString(Stringify.FORMATTED));
            }

            val redisSearchAvailable = isRedisSearchAvailable();
            val principal = getPrincipalIdFrom(ticket);
            val attributesEncoded = redisSearchAvailable ? encodeTicketAttributes(ticket) : null;
            val service = redisSearchAvailable && ticket instanceof final ServiceAwareTicket sat && Objects.nonNull(sat.getService())
                ? sat.getService().getId()
                : null;

            return RedisTicketDocument
                .builder()
                .type(encTicket.getClass().getName())
                .ticketId(encTicket.getId())
                .json(compressTicketJson(json))
                .prefix(ticket.getPrefix())
                .principal(encodePrincipalIdentifier(principal))
                .attributes(attributesEncoded)
                .service(service)
                .build();
        });
    }

    protected Ticket deserializeTicket(final RedisTicketDocument document) {
        return deserializeTicket(decompressTicketJson(document.json()), document.type());
    }

    protected String compressTicketJson(final String json) {
        return CompressionUtils.deflate(json);
    }

    protected String decompressTicketJson(final String json) {
        val text = StringUtils.trim(json);
        if (StringUtils.isBlank(text)) {
            return text;
        }
        if (!text.isEmpty() && (text.charAt(0) == '{' || text.charAt(0) == '[')) {
            return text;
        }
        val decoded = EncodingUtils.decodeBase64(text);
        val inflated = CompressionUtils.inflateToString(decoded);
        return StringUtils.defaultIfBlank(inflated, text);
    }

    private String encodeTicketAttributes(final Ticket ticket) {
        val attributeMap = (Map<String, Object>) collectAndDigestTicketAttributes(ticket);
        return attributeMap
            .entrySet()
            .stream()
            .map(entry -> {
                val entryValues = (List) entry.getValue();
                val valueList = entryValues.parallelStream().map(Object::toString).collect(Collectors.joining(","));
                return entry.getKey() + (isCipherExecutorEnabled() ? " " : "_") + valueList;
            })
            .collect(Collectors.joining(","));
    }

    private boolean isRedisSearchAvailable() {
        return redisModulesOperations.isPresent();
    }

    protected @Nullable Ticket getTicketFromRedis(final Predicate<Ticket> predicate, final String redisKeyPattern,
                                                  final RedisKeyGenerator redisKeyGenerator) {
        return getTicketFromRedis(
            predicate, redisKeyPattern, redisKeyGenerator, true);
    }

    private @Nullable Ticket getTicketFromRedis(
        final Predicate<Ticket> predicate,
        final String redisKeyPattern,
        final RedisKeyGenerator redisKeyGenerator,
        final boolean nearCacheAllowed) {
        val rawTicketId = redisKeyGenerator.rawKey(redisKeyPattern);
        val cachedTicket = nearCacheAllowed
            ? ticketCache.stream()
                .map(cache -> cache.getIfPresent(rawTicketId))
                .filter(Objects::nonNull)
                .findFirst()
            : Optional.<Ticket>empty();

        val ticket = cachedTicket
            .map(this::decodeTicket)
            .filter(predicate)
            .orElseGet(() -> Stream.of(redisKeyPattern)
                .map(key -> {
                    val keyspace = redisKeyGenerator.getKeyspace();
                    return redisKeyValueAdapter.get(rawTicketId, keyspace, RedisTicketDocument.class);
                })
                .filter(Objects::nonNull)
                .map(this::deserializeTicket)
                .map(this::decodeTicket)
                .filter(predicate)
                .findFirst()
                .orElseGet(() -> handleMissingTicket(rawTicketId, redisKeyPattern)));

        if (ticket != null && predicate.test(ticket) && !ticket.isExpired()) {
            ticketCache.ifAvailable(cache -> cache.put(rawTicketId, ticket));
            return ticket;
        }
        ticketCache.ifAvailable(cache -> cache.invalidate(rawTicketId));
        if (ticket != null) {
            messagePublisher.ifAvailable(publisher -> publisher.delete(ticket));
        }
        return null;
    }

    protected Ticket handleMissingTicket(final String rawTicketId, final String redisKey) {
        return null;
    }

    private void addOrUpdateTicket(final Ticket ticket,
                                   final TicketRegistryWriteInterceptor.Operation operation) {
        addOrUpdateTicket(ticket, operation, Optional.empty());
    }

    private void addOrUpdateTicket(
        final Ticket ticket,
        final TicketRegistryWriteInterceptor.Operation operation,
        final TicketIssuanceWriteContext context) {
        addOrUpdateTicket(ticket, operation, Optional.of(Objects.requireNonNull(context, "context")));
    }

    private void addOrUpdateTicket(
        final Ticket ticket,
        final TicketRegistryWriteInterceptor.Operation operation,
        final Optional<TicketIssuanceWriteContext> issuanceContext) {
        val contexts = new ArrayList<TicketRegistryWriteInterceptor.WriteContext>();
        try {
            ticketRegistryWriteInterceptors.orderedStream().forEach(interceptor -> {
                val writeContext = issuanceContext.isPresent()
                    ? interceptor.beforeWrite(ticket, operation, issuanceContext.orElseThrow())
                    : interceptor.beforeWrite(ticket, operation);
                contexts.add(Objects.requireNonNull(writeContext));
            });
        } catch (final Throwable cause) {
            notifyWriteFailure(contexts, ticket, cause, issuanceContext);
            throw rethrowUnchecked(cause);
        }
        val receipt = writeTicketAndPublish(
            ticket, operation, issuanceContext, contexts);
        Throwable callbackFailure = null;
        for (var index = contexts.size() - 1; index >= 0; index--) {
            try {
                if (issuanceContext.isPresent()) {
                    contexts.get(index).succeeded(ticket, receipt, issuanceContext.orElseThrow());
                } else {
                    contexts.get(index).succeeded(ticket, receipt);
                }
            } catch (final Throwable cause) {
                if (callbackFailure == null) {
                    callbackFailure = cause;
                } else {
                    callbackFailure.addSuppressed(cause);
                }
            }
        }
        if (callbackFailure != null) {
            throw new TicketRegistryWriteCompletionException(ticket.getId(), operation, callbackFailure);
        }
    }

    private TicketRegistryWriteReceipt writeTicketAndPublish(
        final Ticket ticket,
        final TicketRegistryWriteInterceptor.Operation operation,
        final Optional<TicketIssuanceWriteContext> issuanceContext,
        final List<TicketRegistryWriteInterceptor.WriteContext> contexts) {
        try {
            val receipt = writeTicket(ticket, operation, issuanceContext);
            messagePublisher.ifAvailable(publisher -> {
                switch (operation) {
                    case ADD -> publisher.add(ticket);
                    case UPDATE -> publisher.update(ticket);
                }
            });
            return receipt;
        } catch (final Throwable cause) {
            notifyWriteFailure(contexts, ticket, cause, issuanceContext);
            throw rethrowUnchecked(cause);
        }
    }

    private static void notifyWriteFailure(
        final List<TicketRegistryWriteInterceptor.WriteContext> contexts,
        final Ticket ticket,
        final Throwable cause,
        final Optional<TicketIssuanceWriteContext> issuanceContext) {
        for (var index = contexts.size() - 1; index >= 0; index--) {
            try {
                if (issuanceContext.isPresent()) {
                    contexts.get(index).failed(ticket, cause, issuanceContext.orElseThrow());
                } else {
                    contexts.get(index).failed(ticket, cause);
                }
            } catch (final Throwable callbackFailure) {
                cause.addSuppressed(callbackFailure);
            }
        }
    }

    private static RuntimeException rethrowUnchecked(final Throwable cause) {
        if (cause instanceof final RuntimeException runtimeException) {
            return runtimeException;
        }
        if (cause instanceof final Error error) {
            throw error;
        }
        return new IllegalStateException("Ticket-registry callback raised a checked exception", cause);
    }

    private TicketRegistryWriteReceipt writeTicket(final Ticket ticket,
                                                    final TicketRegistryWriteInterceptor.Operation operation,
                                                    final Optional<TicketIssuanceWriteContext> issuanceContext) {
        val digestedId = digestIdentifier(ticket.getId());
        val redisKeyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(ticket.getPrefix()).orElseThrow();
        val redisKeyPattern = redisKeyGenerator.forPrefixAndId(ticket.getPrefix(), digestedId);

        val timeout = RedisKeyGenerator.getTicketExpirationInSeconds(ticket);
        val ticketDocument = buildTicketAsDocument(ticket);

        val keyspace = redisKeyGenerator.getKeyspace();
        val redisDataItem = new RedisData();
        redisKeyValueAdapter.getConverter().write(ticketDocument, redisDataItem);
        redisDataItem.setKeyspace(keyspace);
        redisDataItem.setTimeToLive(timeout, TimeUnit.SECONDS);

        val expiresAt = ticket.getExpirationPolicy() instanceof final IdleExpirationPolicy idleExpirationPolicy
            ? idleExpirationPolicy.getIdleExpirationTime(ticket).toInstant()
            : Instant.now(Clock.systemUTC()).plusSeconds(timeout);
        val principalIndex = Optional.ofNullable(ticketDocument.principal())
            .filter(StringUtils::isNotBlank)
            .map(principal -> new RedisTicketRegistryWriteExecutor.PrincipalIndexEntry(
                RedisPrincipalTicketIndexKeyGenerator.prefix(),
                RedisPrincipalTicketIndexKeyGenerator.forPrincipal(principal),
                redisKeyPattern,
                expiresAt.toEpochMilli()));
        val principalMutationFenceKey = Optional.ofNullable(ticketDocument.principal())
            .filter(StringUtils::isNotBlank)
            .map(RedisPrincipalTicketMutationFenceKeyGenerator::forPrincipal);
        val principalSessionIndex = principalIndex
            .filter(_ -> ticket instanceof TicketGrantingTicket)
            .flatMap(_ -> redisKeyGeneratorFactory
                .getRedisKeyGenerator(Principal.class.getName()))
            .map(generator -> {
                val mode = switch (casProperties.getTicket().getTgt().getCore()
                                       .getServiceTrackingPolicy()) {
                    case ALL -> RedisTicketRegistryWriteExecutor.PrincipalSessionIndexMode.ALL;
                    case MOST_RECENT -> RedisTicketRegistryWriteExecutor.PrincipalSessionIndexMode.MOST_RECENT;
                };
                val principal = ticketDocument.principal();
                return new RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry(
                    generator.getNamespace() + ':',
                    generator.forId(principal),
                    serializeSessionIndexMember(digestedId),
                    Math.floorDiv(expiresAt.toEpochMilli(), 1000),
                    mode);
            });
        val command = new RedisTicketRegistryWriteExecutor.WriteCommand(ticket, operation,
            redisKeyPattern, keyspace, ticketDocument.ticketId(), timeout,
            expiresAt.toEpochMilli(), redisDataItem, issuanceContext,
            RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
            principalMutationFenceKey,
            principalIndex, principalSessionIndex);
        val defaultPersistence = (Runnable) () -> persistTicket(command);
        val executors = ticketRegistryWriteExecutors.orderedStream().limit(2).toList();
        if (executors.size() > 1) {
            throw new IllegalStateException("Only one RedisTicketRegistryWriteExecutor may be registered");
        }
        val receipt = executors.isEmpty()
            ? executeDefaultPersistence(defaultPersistence)
            : Objects.requireNonNull(
                executors.getFirst().execute(command, defaultPersistence),
                "Redis ticket write executor receipt");

        /*
         * Keep the near cache read-through. A write-through put here can run
         * after a concurrent registry-wide delete has already swept Redis and
         * invalidated every cache, resurrecting a ticket only in this JVM.
         */
        ticketCache.ifAvailable(cache -> cache.invalidate(digestedId));
        return receipt;
    }

    private static TicketRegistryWriteReceipt executeDefaultPersistence(
        final Runnable defaultPersistence) {
        defaultPersistence.run();
        return TicketRegistryWriteReceipt.unsequenced("ticket-redis");
    }

    private void persistTicket(final RedisTicketRegistryWriteExecutor.WriteCommand command) {
        if (!command.redisData().getIndexedData().isEmpty()) {
            throw new IllegalStateException(
                "Redis principal ticket persistence does not support Spring secondary indexes");
        }
        val bucket = command.redisData().getBucket().rawMap();
        if (bucket.isEmpty()) {
            throw new IllegalStateException("Redis ticket mapping produced an empty hash");
        }
        command.principalIndex().ifPresent(index -> {
            if (!command.redisKey().equals(index.member())
                || command.expiresAtEpochMilli() != index.expiresAtEpochMilli()
                || !index.redisKey().startsWith(index.redisKeyPrefix())) {
                throw new IllegalStateException("Redis principal ticket index coordinates are inconsistent");
            }
        });
        command.principalSessionIndex().ifPresent(index -> {
            if (!index.redisKey().startsWith(index.redisKeyPrefix())
                || index.expiresAtEpochSecond()
                != Math.floorDiv(command.expiresAtEpochMilli(), 1000)) {
                throw new IllegalStateException("Redis principal session index coordinates are inconsistent");
            }
        });

        val keysAndArguments = new ArrayList<byte[]>(
            (bucket.size() * 2) + WRITE_COMMAND_BASE_ARGUMENT_COUNT);
        keysAndArguments.add(command.redisKey().getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.keyspace().getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.mutationFenceKey().getBytes(StandardCharsets.UTF_8));
        command.principalMutationFenceKey()
            .map(key -> key.getBytes(StandardCharsets.UTF_8))
            .ifPresent(keysAndArguments::add);
        command.principalIndex()
            .map(RedisTicketRegistryWriteExecutor.PrincipalIndexEntry::redisKey)
            .map(key -> key.getBytes(StandardCharsets.UTF_8))
            .ifPresent(keysAndArguments::add);
        command.principalSessionIndex()
            .map(RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry::redisKey)
            .map(key -> key.getBytes(StandardCharsets.UTF_8))
            .ifPresent(keysAndArguments::add);
        keysAndArguments.add(Long.toString(command.expiresAtEpochMilli()).getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.documentId().getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(RedisTicketDocument.FIELD_NAME_PRINCIPAL.getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.principalIndex()
            .map(RedisTicketRegistryWriteExecutor.PrincipalIndexEntry::redisKeyPrefix)
            .orElseGet(RedisPrincipalTicketIndexKeyGenerator::prefix)
            .getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.redisKey().getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.principalSessionIndex()
            .map(RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry::redisKeyPrefix)
            .orElse(StringUtils.EMPTY)
            .getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.principalSessionIndex()
            .map(RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry::serializedMember)
            .orElseGet(() -> new byte[0]));
        keysAndArguments.add(command.principalSessionIndex()
            .map(RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry::expiresAtEpochSecond)
            .map(Object::toString)
            .orElse("0")
            .getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(command.principalSessionIndex()
            .map(RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry::mode)
            .map(mode -> mode == RedisTicketRegistryWriteExecutor.PrincipalSessionIndexMode.ALL
                ? "A" : "M")
            .orElse("N")
            .getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(RedisPrincipalTicketMutationFenceKeyGenerator.prefix()
            .getBytes(StandardCharsets.UTF_8));
        keysAndArguments.add(Integer.toString(bucket.size()).getBytes(StandardCharsets.UTF_8));
        bucket.forEach((field, value) -> {
            keysAndArguments.add(field);
            keysAndArguments.add(value);
        });
        val result = casRedisTemplates.getTicketsRedisTemplate().execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                WRITE_TICKET_SCRIPT,
                ReturnType.INTEGER,
                3 + (command.principalMutationFenceKey().isPresent() ? 1 : 0)
                    + (command.principalIndex().isPresent() ? 1 : 0)
                    + (command.principalSessionIndex().isPresent() ? 1 : 0),
                keysAndArguments.toArray(byte[][]::new)));
        if (!Long.valueOf(1).equals(result)) {
            throw new IllegalStateException("Redis ticket write returned an invalid result");
        }
    }

    protected void configureTicketExpirationInstant(final Ticket ticket, final String redisKeyPattern) {
        if (ticket.getExpirationPolicy() instanceof final IdleExpirationPolicy iep) {
            val expirationInstant = iep.getIdleExpirationTime(ticket).toInstant();
            casRedisTemplates.getTicketsRedisTemplate().expireAt(redisKeyPattern, expirationInstant);
            LOGGER.debug("Ticket [{}] will expire at [{}]", ticket.getId(), expirationInstant);
        } else {
            val timeoutSeconds = RedisKeyGenerator.getTicketExpirationInSeconds(ticket);
            casRedisTemplates.getTicketsRedisTemplate().expire(redisKeyPattern, Expiration.from(timeoutSeconds, TimeUnit.SECONDS));
            LOGGER.debug("Ticket [{}] will expire in [{}] second(s)", ticket.getId(), timeoutSeconds);
        }
    }

    private void createIndexesIfNecessary() {
        val indexesOnNamespaces = new HashSet<String>();
        redisModulesOperations.ifPresent(ops ->
            redisKeyGeneratorFactory.getRedisKeyGenerators()
                .stream()
                .filter(RedisKeyGenerator::isTicketKeyGenerator)
                .forEach(redisKeyGenerator -> {
                    val prefix = redisKeyGenerator.getNamespace() + ':';
                    if (!indexesOnNamespaces.contains(prefix)) {
                        val fields = CollectionUtils.wrapList(
                            RedisTicketDocument.FIELD_NAME_ID,
                            RedisTicketDocument.FIELD_NAME_ATTRIBUTES,
                            RedisTicketDocument.FIELD_NAME_PRINCIPAL,
                            RedisTicketDocument.FIELD_NAME_TYPE,
                            RedisTicketDocument.FIELD_NAME_SERVICE,
                            RedisTicketDocument.FIELD_NAME_PREFIX);
                        ops.createIndexes(SEARCH_INDEX_NAME, prefix, fields);
                        indexesOnNamespaces.add(prefix);
                    }
                }));
    }

    record RedisTicketToDelete(String redisKey,
                               String cacheKey,
                               String sessionIndexMember,
                               String keyspace,
                               String documentId,
                               boolean sessionTicket) {
    }

    @Data
    public static class CasRedisTemplates {
        private final CasRedisTemplate<String, RedisTicketDocument> ticketsRedisTemplate;

        private final CasRedisTemplate<String, String> sessionsRedisTemplate;
    }

}
