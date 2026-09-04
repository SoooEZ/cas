package org.apereo.cas.redis.core;

import module java.base;

import lombok.val;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * Same-slot secondary index for principal-owned account-security values.
 *
 * <p>Data, index, index-state, rebuild-lease and terminal-fence keys must use
 * the same Redis Cluster hash slot. Stable reads execute on the Redis authority
 * through Lua, check the terminal fence and consume the complete index at one
 * linearization point. A cardinality-bearing state marker detects a missing or
 * partially lost index without putting a database-wide {@code SCAN} on an
 * authentication path.</p>
 *
 * @author Apereo CAS
 * @param <V> indexed value type
 * @since 8.0.1
 */
public final class RedisAccountSecurityIndexedStore<V> {
    /** Maximum records accepted for one principal. */
    public static final int MAXIMUM_INDEX_ENTRIES = 256;

    private static final int MAXIMUM_INDEX_RETRIES = 16;

    private static final int MAXIMUM_DATA_KEY_LENGTH = 8_192;

    private static final int CAPACITY_RESULT = -3;

    private static final int STATE_NOT_READY_RESULT = -4;

    private static final int RECORD_REVOKED_RESULT = -5;

    private static final int REBUILD_CAPACITY_RESULT = -2;

    private static final int INDEX_EXISTING_REVOKED_RESULT = -2;

    private static final int TERMINAL_FENCED_RESULT = -2;

    private static final int CORRUPT_REDIS_TYPE_RESULT = -3;

    private static final int CORRUPT_MARK_STATE_RESULT = -2;

    private static final byte[] FENCED_INDEXED_SET_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return 0
        end
        if redis.call('EXISTS', KEYS[6]) ~= 0 then
          return -5
        end
        local before = redis.call('SCARD', KEYS[3])
        local index_ttl_before = redis.call('PTTL', KEYS[3])
        local state_ttl_before = redis.call('PTTL', KEYS[4])
        local expires_at = tonumber(ARGV[3])
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        if not expires_at or expires_at <= now_millis then
          return -1
        end
        local capacity = tonumber(ARGV[4])
        local member_exists = redis.call('SISMEMBER', KEYS[3], ARGV[2])
        if before > capacity or (member_exists == 0 and before >= capacity) then
          return -3
        end
        local state = redis.call('GET', KEYS[4])
        if ARGV[5] == '1' then
          if state then
            local expected = string.match(state, '^READY:(%d+)$')
            if not expected or tonumber(expected) ~= before then
              return -4
            end
          elseif before ~= 0 then
            return -4
          end
        end
        local function write_state(value)
          redis.call('SET', KEYS[4], value)
          if state_ttl_before == -1 then
            redis.call('PERSIST', KEYS[4])
          elseif state_ttl_before >= 0 then
            redis.call('PEXPIRE', KEYS[4], state_ttl_before)
          end
        end
        local function update_state(after)
          local current_state = redis.call('GET', KEYS[4])
          if current_state then
            local expected = string.match(current_state, '^READY:(%d+)$')
            if expected then
              if tonumber(expected) == before then
                write_state('READY:' .. after)
              else
                write_state('REBUILD')
              end
            end
          elseif ARGV[5] == '1' and before == 0
              and redis.call('EXISTS', KEYS[5]) == 0 then
            write_state('READY:' .. after)
          else
            write_state('REBUILD')
          end
        end
        local function extend_expiry(key, previous_ttl)
          local remaining = expires_at - now_millis
          if previous_ttl == -2 then
            redis.call('PEXPIREAT', key, expires_at)
          elseif previous_ttl >= 0 and previous_ttl < remaining then
            redis.call('PEXPIREAT', key, expires_at)
          end
        end
        redis.call('SET', KEYS[2], ARGV[1])
        redis.call('PEXPIREAT', KEYS[2], expires_at)
        redis.call('SET', KEYS[7], ARGV[6])
        redis.call('PEXPIREAT', KEYS[7], expires_at)
        redis.call('SADD', KEYS[3], ARGV[2])
        update_state(redis.call('SCARD', KEYS[3]))
        extend_expiry(KEYS[3], index_ttl_before)
        extend_expiry(KEYS[4], state_ttl_before)
        return 1
        """);

    private static final byte[] INDEX_EXISTING_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local fence_type = keytype(KEYS[1])
        local data_type = keytype(KEYS[2])
        local index_type = keytype(KEYS[3])
        local state_type = keytype(KEYS[4])
        local token_type = keytype(KEYS[5])
        local revocation_type = keytype(KEYS[6])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (data_type ~= 'none' and data_type ~= 'string')
            or (index_type ~= 'none' and index_type ~= 'set')
            or (state_type ~= 'none' and state_type ~= 'string')
            or (token_type ~= 'none' and token_type ~= 'string')
            or (revocation_type ~= 'none' and revocation_type ~= 'string') then
          return -3
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return 0
        end
        if redis.call('EXISTS', KEYS[6]) ~= 0 then
          return -2
        end
        local before = redis.call('SCARD', KEYS[3])
        local index_ttl_before = redis.call('PTTL', KEYS[3])
        local state_ttl_before = redis.call('PTTL', KEYS[4])
        local exists = redis.call('EXISTS', KEYS[2])
        local data_ttl = redis.call('PTTL', KEYS[2])
        local token_exists = redis.call('EXISTS', KEYS[5])
        local state = redis.call('GET', KEYS[4])
        if exists ~= 0 and data_ttl ~= -1 and data_ttl <= 0 then
          exists = 0
        end
        if exists ~= 0 then
          local capacity = tonumber(ARGV[2])
          local member_exists = redis.call('SISMEMBER', KEYS[3], ARGV[1])
          if before > capacity or (member_exists == 0 and before >= capacity) then
            return -1
          end
          redis.call('SADD', KEYS[3], ARGV[1])
        else
          redis.call('SREM', KEYS[3], ARGV[1])
        end
        local after = redis.call('SCARD', KEYS[3])
        local function write_state(value)
          redis.call('SET', KEYS[4], value)
          if state_ttl_before == -1 then
            redis.call('PERSIST', KEYS[4])
          elseif state_ttl_before >= 0 then
            redis.call('PEXPIRE', KEYS[4], state_ttl_before)
          end
        end
        if state then
          local expected = string.match(state, '^READY:(%d+)$')
          if expected then
            if tonumber(expected) == before then
              write_state('READY:' .. after)
            else
              write_state('REBUILD')
            end
          end
        elseif after ~= 0 then
          write_state('REBUILD')
        end
        if exists ~= 0 then
          if token_exists == 0 then
            redis.call('SET', KEYS[5], ARGV[3])
          end
          if data_ttl == -1 then
            redis.call('PERSIST', KEYS[5])
            redis.call('PERSIST', KEYS[3])
            redis.call('PERSIST', KEYS[4])
          elseif data_ttl > 0 then
            redis.call('PEXPIRE', KEYS[5], data_ttl)
            if index_ttl_before == -2
                or (index_ttl_before >= 0 and index_ttl_before < data_ttl) then
              redis.call('PEXPIRE', KEYS[3], data_ttl)
            end
            if state_ttl_before == -2
                or (state_ttl_before >= 0 and state_ttl_before < data_ttl) then
              redis.call('PEXPIRE', KEYS[4], data_ttl)
            end
          end
        else
          redis.call('DEL', KEYS[5])
        end
        return exists == 0 and 2 or 1
        """);

    private static final byte[] DELETE_INDEXED_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[4]) ~= 0 then
          return 2
        end
        local before = redis.call('SCARD', KEYS[2])
        local state = redis.call('GET', KEYS[3])
        local state_ttl = redis.call('PTTL', KEYS[3])
        redis.call('DEL', KEYS[1])
        redis.call('DEL', KEYS[5])
        redis.call('SREM', KEYS[2], ARGV[1])
        local after = redis.call('SCARD', KEYS[2])
        local function write_state(value)
          redis.call('SET', KEYS[3], value)
          if state_ttl >= 0 then
            redis.call('PEXPIRE', KEYS[3], state_ttl)
          end
        end
        if state then
          local expected = string.match(state, '^READY:(%d+)$')
          if expected then
            if tonumber(expected) == before then
              if after == 0 then
                redis.call('DEL', KEYS[2])
                redis.call('DEL', KEYS[3])
              else
                write_state('READY:' .. after)
              end
            else
              write_state('REBUILD')
            end
          end
        elseif after ~= 0 then
          write_state('REBUILD')
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0
            or redis.call('EXISTS', KEYS[5]) ~= 0
            or redis.call('SISMEMBER', KEYS[2], ARGV[1]) ~= 0 then
          return 0
        end
        return 1
        """);

    private static final byte[] COMPARE_AND_DELETE_INDEXED_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[4]) ~= 0 then
          return 3
        end
        local current = redis.call('GET', KEYS[1])
        local current_token = redis.call('GET', KEYS[5])
        if (current and current ~= ARGV[2])
            or (current and current_token ~= ARGV[3])
            or (not current and current_token) then
          return 0
        end
        local before = redis.call('SCARD', KEYS[2])
        local state = redis.call('GET', KEYS[3])
        local state_ttl = redis.call('PTTL', KEYS[3])
        local deleted = current and 1 or 2
        if current then
          redis.call('DEL', KEYS[1])
        end
        redis.call('DEL', KEYS[5])
        redis.call('SREM', KEYS[2], ARGV[1])
        local after = redis.call('SCARD', KEYS[2])
        local function write_state(value)
          redis.call('SET', KEYS[3], value)
          if state_ttl >= 0 then
            redis.call('PEXPIRE', KEYS[3], state_ttl)
          end
        end
        if state then
          local expected = string.match(state, '^READY:(%d+)$')
          if expected then
            if tonumber(expected) == before then
              if after == 0 then
                redis.call('DEL', KEYS[2])
                redis.call('DEL', KEYS[3])
              else
                write_state('READY:' .. after)
              end
            else
              write_state('REBUILD')
            end
          end
        elseif after ~= 0 then
          write_state('REBUILD')
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0
            or redis.call('EXISTS', KEYS[5]) ~= 0
            or redis.call('SISMEMBER', KEYS[2], ARGV[1]) ~= 0 then
          return -1
        end
        return deleted
        """);

    private static final byte[] REVOKE_INDEXED_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[5]) ~= 0 then
          return -2
        end
        local expires_at = tonumber(ARGV[2])
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        if not expires_at or expires_at <= now_millis then
          return -1
        end
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local data_type = keytype(KEYS[1])
        local index_type = keytype(KEYS[2])
        local state_type = keytype(KEYS[3])
        local revocation_type = keytype(KEYS[4])
        local token_type = keytype(KEYS[6])
        if (data_type ~= 'none' and data_type ~= 'string')
            or (index_type ~= 'none' and index_type ~= 'set')
            or (state_type ~= 'none' and state_type ~= 'string')
            or (revocation_type ~= 'none' and revocation_type ~= 'string')
            or (token_type ~= 'none' and token_type ~= 'string') then
          return -3
        end
        local fence_ttl = redis.call('PTTL', KEYS[4])
        local data_ttl = redis.call('PTTL', KEYS[1])
        local before = redis.call('SCARD', KEYS[2])
        local state = redis.call('GET', KEYS[3])
        local state_ttl = redis.call('PTTL', KEYS[3])
        local persistent_authority = data_type ~= 'none' and data_ttl == -1
        if data_ttl > 0 and now_millis + data_ttl > expires_at then
          expires_at = now_millis + data_ttl
        end
        local remaining = expires_at - now_millis
        redis.call('SET', KEYS[4], 'REVOKED')
        if fence_ttl == -1 or persistent_authority then
          redis.call('PERSIST', KEYS[4])
        elseif fence_ttl > remaining then
          redis.call('PEXPIRE', KEYS[4], fence_ttl)
        else
          redis.call('PEXPIREAT', KEYS[4], expires_at)
        end
        redis.call('DEL', KEYS[1])
        redis.call('DEL', KEYS[6])
        redis.call('SREM', KEYS[2], ARGV[1])
        local after = redis.call('SCARD', KEYS[2])
        local function write_state(value)
          redis.call('SET', KEYS[3], value)
          if state_ttl >= 0 then
            redis.call('PEXPIRE', KEYS[3], state_ttl)
          end
        end
        if state then
          local expected = string.match(state, '^READY:(%d+)$')
          if expected then
            if tonumber(expected) == before then
              if after == 0 then
                redis.call('DEL', KEYS[2])
                redis.call('DEL', KEYS[3])
              else
                write_state('READY:' .. after)
              end
            else
              write_state('REBUILD')
            end
          end
        elseif before ~= 0 then
          write_state('REBUILD')
        end
        if redis.call('EXISTS', KEYS[4]) == 0
            or redis.call('EXISTS', KEYS[1]) ~= 0
            or redis.call('EXISTS', KEYS[6]) ~= 0
            or redis.call('SISMEMBER', KEYS[2], ARGV[1]) ~= 0 then
          return 0
        end
        return 1
        """);

    private static final byte[] BOUNDED_INDEX_MEMBERS_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local fence_type = keytype(KEYS[1])
        local index_type = keytype(KEYS[2])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (index_type ~= 'none' and index_type ~= 'set') then
          return {'CORRUPT'}
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return {'FENCED'}
        end
        local cardinality = redis.call('SCARD', KEYS[2])
        if cardinality > tonumber(ARGV[1]) then
          return {'CAPACITY'}
        end
        local result = {'MEMBERS'}
        local members = redis.call('SMEMBERS', KEYS[2])
        for _, member in ipairs(members) do
          table.insert(result, member)
        end
        return result
        """);

    private static final byte[] INDEXED_AUTHORITY_READ_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local fence_type = keytype(KEYS[1])
        local index_type = keytype(KEYS[2])
        local state_type = keytype(KEYS[3])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (index_type ~= 'none' and index_type ~= 'set')
            or (state_type ~= 'none' and state_type ~= 'string') then
          return {'CORRUPT'}
        end
        for index = 4, #KEYS, 2 do
          local data_type = keytype(KEYS[index])
          local token_type = keytype(KEYS[index + 1])
          if (data_type ~= 'none' and data_type ~= 'string')
              or (token_type ~= 'none' and token_type ~= 'string') then
            return {'CORRUPT'}
          end
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return {'FENCED'}
        end
        if ((#KEYS - 3) % 2) ~= 0 then
          return {'REBUILD'}
        end
        local supplied = (#KEYS - 3) / 2
        local cardinality = redis.call('SCARD', KEYS[2])
        local state = redis.call('GET', KEYS[3])
        if not state and cardinality == 0 then
          if supplied ~= 0 then
            return {'RETRY'}
          end
          if ARGV[3] == '1' then
            return {'EMPTY'}
          end
          return {'REBUILD'}
        end
        local expected = state and string.match(state, '^READY:(%d+)$') or nil
        if not expected then
          return {'REBUILD'}
        end
        if tonumber(expected) ~= cardinality or cardinality > tonumber(ARGV[2]) then
          local state_ttl = redis.call('PTTL', KEYS[3])
          redis.call('SET', KEYS[3], 'REBUILD')
          if state_ttl >= 0 then
            redis.call('PEXPIRE', KEYS[3], state_ttl)
          end
          return {'REBUILD'}
        end
        if cardinality ~= supplied then
          return {'RETRY'}
        end
        for index = 4, #KEYS, 2 do
          if string.sub(KEYS[index], 1, string.len(ARGV[1])) ~= ARGV[1]
              or KEYS[index + 1] ~= KEYS[index] .. ':write-token'
              or redis.call('SISMEMBER', KEYS[2], KEYS[index]) == 0 then
            return {'RETRY'}
          end
        end
        local result = {'READY'}
        local maximum_ttl = 0
        local persistent_member = false
        for index = 4, #KEYS, 2 do
          local ttl = redis.call('PTTL', KEYS[index])
          local current = redis.call('GET', KEYS[index])
          local current_token = redis.call('GET', KEYS[index + 1])
          local token_ttl = redis.call('PTTL', KEYS[index + 1])
          local current_live = current and (ttl == -1 or ttl > 0)
          if current_live then
            if not current_token or (token_ttl ~= -1 and token_ttl <= 0) then
              local state_ttl = redis.call('PTTL', KEYS[3])
              redis.call('SET', KEYS[3], 'REBUILD')
              if state_ttl >= 0 then
                redis.call('PEXPIRE', KEYS[3], state_ttl)
              end
              return {'REBUILD'}
            end
            table.insert(result, KEYS[index])
            table.insert(result, current)
            table.insert(result, current_token)
            if ttl == -1 then
              persistent_member = true
            elseif ttl > maximum_ttl then
              maximum_ttl = ttl
            end
          else
            redis.call('SREM', KEYS[2], KEYS[index])
            redis.call('DEL', KEYS[index + 1])
          end
        end
        local updated = redis.call('SCARD', KEYS[2])
        if updated == 0 then
          redis.call('DEL', KEYS[2])
          redis.call('DEL', KEYS[3])
        elseif updated ~= cardinality then
          redis.call('SET', KEYS[3], 'READY:' .. updated)
        end
        if updated > 0 then
          if persistent_member then
            redis.call('PERSIST', KEYS[2])
            redis.call('PERSIST', KEYS[3])
          elseif maximum_ttl > 0 then
            redis.call('PEXPIRE', KEYS[2], maximum_ttl)
            redis.call('PEXPIRE', KEYS[3], maximum_ttl)
          end
        end
        return result
        """);

    private static final byte[] ACQUIRE_REBUILD_LEASE_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local fence_type = keytype(KEYS[1])
        local index_type = keytype(KEYS[2])
        local state_type = keytype(KEYS[3])
        local lease_type = keytype(KEYS[4])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (index_type ~= 'none' and index_type ~= 'set')
            or (state_type ~= 'none' and state_type ~= 'string')
            or (lease_type ~= 'none' and lease_type ~= 'string') then
          return -3
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return -1
        end
        local state = redis.call('GET', KEYS[3])
        local current = redis.call('GET', KEYS[4])
        local expected = state and string.match(state, '^READY:(%d+)$') or nil
        local cardinality = redis.call('SCARD', KEYS[2])
        if expected and tonumber(expected) == cardinality
            and cardinality <= tonumber(ARGV[3]) then
          return 2
        end
        if state ~= 'REBUILD' then
          local state_ttl = redis.call('PTTL', KEYS[3])
          redis.call('SET', KEYS[3], 'REBUILD')
          if state_ttl >= 0 then
            redis.call('PEXPIRE', KEYS[3], state_ttl)
          end
        end
        if not current then
          redis.call('SET', KEYS[4], ARGV[1], 'PX', ARGV[2])
          return 1
        end
        if current == ARGV[1] then
          redis.call('PEXPIRE', KEYS[4], ARGV[2])
          return 1
        end
        return 0
        """);

    private static final byte[] COMPLETE_REBUILD_SCRIPT = script("""
        if ((#KEYS - 4) % 2) ~= 0 then
          return 2
        end
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function valid_token(value)
          if not value or string.len(value) ~= 36
              or string.sub(value, 9, 9) ~= '-'
              or string.sub(value, 14, 14) ~= '-'
              or string.sub(value, 19, 19) ~= '-'
              or string.sub(value, 24, 24) ~= '-' then
            return false
          end
          local compact, count = string.gsub(value, '%-', '')
          return count == 4 and compact ~= string.rep('0', 32)
              and string.match(compact, '^[0-9a-f]+$') ~= nil
        end
        local fence_type = keytype(KEYS[1])
        local index_type = keytype(KEYS[2])
        local state_type = keytype(KEYS[3])
        local lease_type = keytype(KEYS[4])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (index_type ~= 'none' and index_type ~= 'set')
            or (state_type ~= 'none' and state_type ~= 'string')
            or (lease_type ~= 'none' and lease_type ~= 'string') then
          return 4
        end
        for index = 5, #KEYS, 2 do
          local data_type = keytype(KEYS[index])
          local token_type = keytype(KEYS[index + 1])
          if (data_type ~= 'none' and data_type ~= 'string')
              or (token_type ~= 'none' and token_type ~= 'string') then
            return 4
          end
          local data_ttl = redis.call('PTTL', KEYS[index])
          local data_live = data_type ~= 'none' and (data_ttl == -1 or data_ttl > 0)
          if data_live and not valid_token(redis.call('GET', KEYS[index + 1])) then
            return 3
          end
        end
        local current_lease = redis.call('GET', KEYS[4])
        if not current_lease or current_lease ~= ARGV[1] then
          return 0
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          redis.call('DEL', KEYS[4])
          return -1
        end
        local cardinality = redis.call('SCARD', KEYS[2])
        if cardinality > tonumber(ARGV[3]) then
          redis.call('DEL', KEYS[3])
          redis.call('DEL', KEYS[4])
          return -2
        end
        local supplied = (#KEYS - 4) / 2
        if cardinality ~= supplied then
          return 2
        end
        for index = 5, #KEYS, 2 do
          if string.sub(KEYS[index], 1, string.len(ARGV[2])) ~= ARGV[2]
              or KEYS[index + 1] ~= KEYS[index] .. ':write-token'
              or redis.call('SISMEMBER', KEYS[2], KEYS[index]) == 0 then
            return 2
          end
        end
        local maximum_ttl = 0
        local persistent_member = false
        for index = 5, #KEYS, 2 do
          local ttl = redis.call('PTTL', KEYS[index])
          local data_live = redis.call('EXISTS', KEYS[index]) ~= 0
              and (ttl == -1 or ttl > 0)
          if not data_live then
            redis.call('SREM', KEYS[2], KEYS[index])
            redis.call('DEL', KEYS[index + 1])
          else
            if ttl == -1 then
              redis.call('PERSIST', KEYS[index + 1])
              persistent_member = true
            else
              redis.call('PEXPIRE', KEYS[index + 1], ttl)
              if ttl > maximum_ttl then
                maximum_ttl = ttl
              end
            end
          end
        end
        cardinality = redis.call('SCARD', KEYS[2])
        if cardinality > tonumber(ARGV[3]) then
          redis.call('DEL', KEYS[3])
          redis.call('DEL', KEYS[4])
          return -2
        end
        if cardinality == 0 then
          redis.call('DEL', KEYS[2])
          redis.call('DEL', KEYS[3])
          redis.call('DEL', KEYS[4])
          return 1
        end
        redis.call('SET', KEYS[3], 'READY:' .. cardinality)
        if persistent_member then
          redis.call('PERSIST', KEYS[2])
          redis.call('PERSIST', KEYS[3])
        elseif maximum_ttl > 0 then
          redis.call('PEXPIRE', KEYS[2], maximum_ttl)
          redis.call('PEXPIRE', KEYS[3], maximum_ttl)
        end
        redis.call('DEL', KEYS[4])
        return 1
        """);

    private static final byte[] RELEASE_REBUILD_LEASE_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if current and current == ARGV[1] then
          redis.call('DEL', KEYS[1])
          return 1
        end
        return 0
        """);

    private static final byte[] ACQUIRE_SCHEMA_LEASE_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local state_type = keytype(KEYS[1])
        local lease_type = keytype(KEYS[2])
        if (state_type ~= 'none' and state_type ~= 'string')
            or (lease_type ~= 'none' and lease_type ~= 'string') then
          return -1
        end
        if redis.call('GET', KEYS[1]) == 'READY' then
          return 2
        end
        local current = redis.call('GET', KEYS[2])
        if not current then
          redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
          return 1
        end
        if current == ARGV[1] then
          redis.call('PEXPIRE', KEYS[2], ARGV[2])
          return 1
        end
        return 0
        """);

    private static final byte[] COMPLETE_SCHEMA_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local state_type = keytype(KEYS[1])
        local lease_type = keytype(KEYS[2])
        if (state_type ~= 'none' and state_type ~= 'string')
            or (lease_type ~= 'none' and lease_type ~= 'string') then
          return -1
        end
        local current = redis.call('GET', KEYS[2])
        if not current or current ~= ARGV[1] then
          return 0
        end
        redis.call('SET', KEYS[1], 'READY')
        redis.call('DEL', KEYS[2])
        return 1
        """);

    private static final byte[] MARK_REBUILD_REQUIRED_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local fence_type = keytype(KEYS[1])
        local state_type = keytype(KEYS[2])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (state_type ~= 'none' and state_type ~= 'string') then
          return -2
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return -1
        end
        local expires_at = tonumber(ARGV[1])
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        if not expires_at or expires_at <= now_millis then
          return 0
        end
        local remaining = expires_at - now_millis
        local existing_ttl = redis.call('PTTL', KEYS[2])
        redis.call('SET', KEYS[2], 'REBUILD')
        if existing_ttl == -1 then
          redis.call('PERSIST', KEYS[2])
        elseif existing_ttl > remaining then
          redis.call('PEXPIRE', KEYS[2], existing_ttl)
        else
          redis.call('PEXPIREAT', KEYS[2], expires_at)
        end
        return 1
        """);

    private static final byte[] MARK_ADOPTION_REQUIRED_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local fence_type = keytype(KEYS[1])
        local state_type = keytype(KEYS[2])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (state_type ~= 'none' and state_type ~= 'string') then
          return -2
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return -1
        end
        local expires_at = ARGV[1] ~= '' and tonumber(ARGV[1]) or nil
        local now_millis = nil
        if expires_at then
          local now = redis.call('TIME')
          now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
          if expires_at <= now_millis then
            return 0
          end
        end
        local state = redis.call('GET', KEYS[2])
        if state and string.match(state, '^READY:%d+$') then
          return 2
        end
        local existing_ttl = redis.call('PTTL', KEYS[2])
        redis.call('SET', KEYS[2], 'ADOPTING:' .. ARGV[2])
        if existing_ttl == -1 then
          redis.call('PERSIST', KEYS[2])
        elseif expires_at then
          local remaining = expires_at - now_millis
          if existing_ttl > remaining then
            redis.call('PEXPIRE', KEYS[2], existing_ttl)
          else
            redis.call('PEXPIREAT', KEYS[2], expires_at)
          end
        end
        return 1
        """);

    private static final byte[] COMPLETE_ADOPTION_SCRIPT = script("""
        if ((#KEYS - 3) % 2) ~= 0 then
          return 2
        end
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function valid_token(value)
          if not value or string.len(value) ~= 36
              or string.sub(value, 9, 9) ~= '-'
              or string.sub(value, 14, 14) ~= '-'
              or string.sub(value, 19, 19) ~= '-'
              or string.sub(value, 24, 24) ~= '-' then
            return false
          end
          local compact, count = string.gsub(value, '%-', '')
          return count == 4 and compact ~= string.rep('0', 32)
              and string.match(compact, '^[0-9a-f]+$') ~= nil
        end
        local fence_type = keytype(KEYS[1])
        local index_type = keytype(KEYS[2])
        local state_type = keytype(KEYS[3])
        if (fence_type ~= 'none' and fence_type ~= 'string')
            or (index_type ~= 'none' and index_type ~= 'set')
            or (state_type ~= 'none' and state_type ~= 'string') then
          return 5
        end
        for index = 4, #KEYS, 2 do
          local data_type = keytype(KEYS[index])
          local token_type = keytype(KEYS[index + 1])
          if (data_type ~= 'none' and data_type ~= 'string')
              or (token_type ~= 'none' and token_type ~= 'string') then
            return 5
          end
          local data_ttl = redis.call('PTTL', KEYS[index])
          local data_live = data_type ~= 'none' and (data_ttl == -1 or data_ttl > 0)
          if data_live and not valid_token(redis.call('GET', KEYS[index + 1])) then
            return 3
          end
        end
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return -1
        end
        local state = redis.call('GET', KEYS[3])
        if state and string.match(state, '^READY:%d+$') then
          return 4
        end
        if state ~= 'ADOPTING:' .. ARGV[3] then
          return 0
        end
        local cardinality = redis.call('SCARD', KEYS[2])
        if cardinality > tonumber(ARGV[2]) then
          return -2
        end
        local supplied = (#KEYS - 3) / 2
        if cardinality ~= supplied then
          return 2
        end
        for index = 4, #KEYS, 2 do
          if string.sub(KEYS[index], 1, string.len(ARGV[1])) ~= ARGV[1]
              or KEYS[index + 1] ~= KEYS[index] .. ':write-token'
              or redis.call('SISMEMBER', KEYS[2], KEYS[index]) == 0 then
            return 2
          end
        end
        local maximum_ttl = 0
        local persistent_member = false
        for index = 4, #KEYS, 2 do
          local ttl = redis.call('PTTL', KEYS[index])
          local data_live = redis.call('EXISTS', KEYS[index]) ~= 0
              and (ttl == -1 or ttl > 0)
          if not data_live then
            redis.call('SREM', KEYS[2], KEYS[index])
            redis.call('DEL', KEYS[index + 1])
          else
            if ttl == -1 then
              redis.call('PERSIST', KEYS[index + 1])
              persistent_member = true
            else
              redis.call('PEXPIRE', KEYS[index + 1], ttl)
              if ttl > maximum_ttl then
                maximum_ttl = ttl
              end
            end
          end
        end
        cardinality = redis.call('SCARD', KEYS[2])
        if cardinality > tonumber(ARGV[2]) then
          return -2
        end
        if cardinality == 0 then
          redis.call('DEL', KEYS[2])
          redis.call('DEL', KEYS[3])
          return 1
        end
        redis.call('SET', KEYS[3], 'READY:' .. cardinality)
        if persistent_member then
          redis.call('PERSIST', KEYS[2])
          redis.call('PERSIST', KEYS[3])
        elseif maximum_ttl > 0 then
          redis.call('PEXPIRE', KEYS[2], maximum_ttl)
          redis.call('PEXPIRE', KEYS[3], maximum_ttl)
        end
        return 1
        """);

    private final CasRedisTemplate<String, V> redisTemplate;

    private final RedisAccountSecurityDeletionFence deletionFence;

    public RedisAccountSecurityIndexedStore(
        final CasRedisTemplate<String, V> redisTemplate,
        final RedisAccountSecurityDeletionFence deletionFence) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.deletionFence = Objects.requireNonNull(deletionFence, "deletionFence");
        if (!Objects.equals(deletionFence.getRedisTemplate(), redisTemplate)) {
            throw new IllegalArgumentException(
                "Account security index and deletion fence must share one Redis authority");
        }
    }

    /**
     * Atomically set and index a principal-owned value while unfenced.
     *
     * @param rawPrincipal principal
     * @param dataKey data key
     * @param indexKey index key
     * @param stateKey cardinality state key
     * @param leaseKey rebuild-lease key
     * @param recordRevocationKey exact-record revocation fence key
     * @param writeToken unique authority-write token
     * @param value value
     * @param expiresAt absolute expiry
     * @param initializeState whether a completed schema cutover permits a new
     * principal to initialize its ready marker
     * @return exact serialized value written to the authority
     */
    public byte[] setIfUnfenced(
        final String rawPrincipal,
        final String dataKey,
        final String indexKey,
        final String stateKey,
        final String leaseKey,
        final String recordRevocationKey,
        final UUID writeToken,
        final V value,
        final Instant expiresAt,
        final boolean initializeState) {
        Objects.requireNonNull(value, "value");
        val expiry = Objects.requireNonNull(expiresAt, "expiresAt");
        val serializedValue = value(value);
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(rawPrincipal);
        val tokenKey = writeTokenKey(dataKey);
        requireRecordRevocationKey(dataKey, recordRevocationKey);
        requireKeysShareSlot(List.of(
            fenceKey, dataKey, indexKey, stateKey, leaseKey, recordRevocationKey, tokenKey));
        val result = evalInteger(
            FENCED_INDEXED_SET_SCRIPT,
            List.of(fenceKey, dataKey, indexKey, stateKey, leaseKey, recordRevocationKey, tokenKey),
            serializedValue,
            key(dataKey),
            ascii(Long.toString(expiry.toEpochMilli())),
            ascii(Integer.toString(MAXIMUM_INDEX_ENTRIES)),
            ascii(initializeState ? "1" : "0"),
            token(writeToken));
        if (result == 0) {
            throw new RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException();
        }
        if (result == -1) {
            throw new IllegalArgumentException("Account security value expires before it can be stored");
        }
        if (result == CAPACITY_RESULT) {
            throw new AccountSecurityIndexedWriteRejectedException(
                "Account security principal exceeds indexed-record capacity");
        }
        if (result == STATE_NOT_READY_RESULT) {
            throw new AccountSecurityIndexedWriteRejectedException(
                "Account security index state requires offline repair");
        }
        if (result == RECORD_REVOKED_RESULT) {
            throw new AccountSecurityRecordRevokedException();
        }
        if (result != 1) {
            throw new IllegalStateException("Unexpected account security indexed-set result");
        }
        return serializedValue.clone();
    }

    /**
     * Read all indexed values at the same authority point as the terminal fence.
     *
     * @param rawPrincipal principal
     * @param indexKey index key
     * @param stateKey state key
     * @param dataKeyPrefix required current-format data-key prefix
     * @param absentStateIsEmpty whether completed schema adoption proves an
     * absent state plus empty index is a new principal
     * @return indexed read result
     */
    public IndexedReadResult<V> read(
        final String rawPrincipal,
        final String indexKey,
        final String stateKey,
        final String dataKeyPrefix,
        final boolean absentStateIsEmpty) {
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(rawPrincipal);
        requireKeysShareSlot(List.of(fenceKey, indexKey, stateKey, dataKeyPrefix));
        for (var attempt = 0; attempt < MAXIMUM_INDEX_RETRIES; attempt++) {
            val snapshot = loadBoundedIndexMembers(fenceKey, indexKey);
            if (snapshot.status() == IndexMemberSnapshotStatus.FENCED) {
                return new IndexedReadResult<>(IndexedReadStatus.FENCED, List.of());
            }
            if (snapshot.status() == IndexMemberSnapshotStatus.CAPACITY_EXCEEDED) {
                return new IndexedReadResult<>(IndexedReadStatus.REBUILD_REQUIRED, List.of());
            }
            val keys = explicitAuthorityKeys(
                List.of(fenceKey, indexKey, stateKey), dataKeyPrefix, snapshot.members());
            val result = evalMulti(
                INDEXED_AUTHORITY_READ_SCRIPT,
                keys,
                key(dataKeyPrefix),
                ascii(Integer.toString(MAXIMUM_INDEX_ENTRIES)),
                ascii(absentStateIsEmpty ? "1" : "0"));
            if (result.isEmpty()) {
                throw new IllegalStateException("Redis indexed authority returned no status");
            }
            val status = utf8(result.getFirst());
            if ("RETRY".equals(status)) {
                continue;
            }
            return switch (status) {
                case "FENCED" -> statusOnly(result, IndexedReadStatus.FENCED);
                case "REBUILD" -> statusOnly(result, IndexedReadStatus.REBUILD_REQUIRED);
                case "EMPTY" -> statusOnly(result, IndexedReadStatus.READY);
                case "READY" -> readyResult(result, dataKeyPrefix);
                case "CORRUPT" -> throw new IllegalStateException(
                    "Redis indexed authority contains corrupt key types");
                default -> throw new IllegalStateException(
                    "Redis indexed authority returned an unknown status");
            };
        }
        throw new ConcurrentModificationException(
            "Account security index changed during bounded authority read");
    }

    /**
     * Add an already-present current value to the index without rewriting it.
     *
     * @param rawPrincipal principal
     * @param dataKey data key
     * @param indexKey index key
     * @param stateKey state key
     * @param writeToken unique adoption/rebuild write token
     * @return indexing result
     */
    public IndexExistingResult indexExistingIfUnfenced(
        final String rawPrincipal,
        final String dataKey,
        final String indexKey,
        final String stateKey,
        final UUID writeToken) {
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(rawPrincipal);
        val tokenKey = writeTokenKey(dataKey);
        val recordRevocationKey = dataKey + ":revoked";
        requireKeysShareSlot(List.of(
            fenceKey, dataKey, indexKey, stateKey, tokenKey, recordRevocationKey));
        val result = evalInteger(
            INDEX_EXISTING_SCRIPT,
            List.of(fenceKey, dataKey, indexKey, stateKey, tokenKey, recordRevocationKey),
            key(dataKey),
            ascii(Integer.toString(MAXIMUM_INDEX_ENTRIES)),
            token(writeToken));
        return switch (Math.toIntExact(result)) {
            case 0 -> IndexExistingResult.FENCED;
            case 1 -> IndexExistingResult.INDEXED;
            case 2 -> IndexExistingResult.ABSENT;
            case INDEX_EXISTING_REVOKED_RESULT -> IndexExistingResult.REVOKED;
            case -1 -> throw new IllegalStateException(
                "Account security principal exceeds indexed-record capacity");
            case CORRUPT_REDIS_TYPE_RESULT -> throw new IllegalStateException(
                "Account security index-existing found corrupt Redis types");
            default -> throw new IllegalStateException(
                "Unexpected account security index-existing result");
        };
    }

    /**
     * Delete one value and its index membership at a single authority point.
     *
     * @param dataKey data key
     * @param indexKey index key
     * @param stateKey state key
     * @return true when both value and membership are absent
     */
    public boolean deleteAndVerify(
        final String dataKey,
        final String indexKey,
        final String stateKey) {
        val fenceKey = terminalFenceKey(dataKey);
        val tokenKey = writeTokenKey(dataKey);
        requireKeysShareSlot(List.of(dataKey, indexKey, stateKey, fenceKey, tokenKey));
        val result = evalInteger(
            DELETE_INDEXED_SCRIPT,
            List.of(dataKey, indexKey, stateKey, fenceKey, tokenKey),
            key(dataKey));
        return result == 1;
    }

    /**
     * Delete one value and its index membership only when the serialized value
     * still equals the authority bytes observed by the caller. A concurrent
     * refresh therefore survives stale expiry cleanup or record revocation.
     *
     * @param dataKey data key
     * @param indexKey index key
     * @param stateKey state key
     * @param expectedSerializedValue exact authority bytes
     * @param expectedWriteToken authority token observed with the value
     * @return conditional deletion result
     */
    public CompareAndDeleteIndexedResult deleteIfUnchanged(
        final String dataKey,
        final String indexKey,
        final String stateKey,
        final byte[] expectedSerializedValue,
        final UUID expectedWriteToken) {
        val fenceKey = terminalFenceKey(dataKey);
        val tokenKey = writeTokenKey(dataKey);
        requireKeysShareSlot(List.of(dataKey, indexKey, stateKey, fenceKey, tokenKey));
        val expected = Objects.requireNonNull(expectedSerializedValue, "expectedSerializedValue").clone();
        if (expected.length == 0) {
            throw new IllegalArgumentException("Account security indexed delete value is empty");
        }
        val result = evalInteger(
            COMPARE_AND_DELETE_INDEXED_SCRIPT,
            List.of(dataKey, indexKey, stateKey, fenceKey, tokenKey),
            key(dataKey),
            expected,
            token(expectedWriteToken));
        return switch (Math.toIntExact(result)) {
            case 0 -> CompareAndDeleteIndexedResult.COMPARE_MISMATCH;
            case 1 -> CompareAndDeleteIndexedResult.DELETED;
            case 2 -> CompareAndDeleteIndexedResult.ABSENT;
            case 3 -> CompareAndDeleteIndexedResult.FENCED;
            case -1 -> throw new IllegalStateException(
                "Unable to verify account security indexed deletion");
            default -> throw new IllegalStateException(
                "Unexpected account security indexed compare-and-delete result");
        };
    }

    /**
     * Fence one exact record until its declared expiry, then atomically remove
     * its authority value and membership. A delayed writer checks the same-slot
     * fence in {@link #setIfUnfenced} and therefore cannot resurrect a revoked
     * record after a coordinate-level removal lease expires.
     *
     * @param dataKey data key
     * @param indexKey index key
     * @param stateKey state key
     * @param recordRevocationKey exact-record revocation fence key
     * @param expiresAt latest candidate or authority expiry
     * @return exact revocation outcome
     */
    public RecordRevocationResult revokeAndVerify(
        final String dataKey,
        final String indexKey,
        final String stateKey,
        final String recordRevocationKey,
        final Instant expiresAt) {
        val fenceKey = terminalFenceKey(dataKey);
        val tokenKey = writeTokenKey(dataKey);
        requireRecordRevocationKey(dataKey, recordRevocationKey);
        requireKeysShareSlot(List.of(
            dataKey, indexKey, stateKey, recordRevocationKey, fenceKey, tokenKey));
        val result = evalInteger(
            REVOKE_INDEXED_SCRIPT,
            List.of(dataKey, indexKey, stateKey, recordRevocationKey, fenceKey, tokenKey),
            key(dataKey),
            ascii(Long.toString(
                Objects.requireNonNull(expiresAt, "expiresAt").toEpochMilli())));
        return switch (Math.toIntExact(result)) {
            case TERMINAL_FENCED_RESULT -> RecordRevocationResult.TERMINAL_FENCED;
            case -1 -> RecordRevocationResult.EXPIRED;
            case 1 -> RecordRevocationResult.REVOKED;
            case CORRUPT_REDIS_TYPE_RESULT -> throw new IllegalStateException(
                "Account security record revocation found corrupt Redis types");
            default -> throw new IllegalStateException(
                "Unable to verify account security record revocation");
        };
    }

    /**
     * Acquire or observe the bounded per-principal index-rebuild lease.
     *
     * @param rawPrincipal principal
     * @param indexKey index key
     * @param stateKey state key
     * @param leaseKey lease key
     * @param leaseToken owner token
     * @param leaseDuration lease duration
     * @return lease result
     */
    public RebuildLeaseResult acquireRebuildLease(
        final String rawPrincipal,
        final String indexKey,
        final String stateKey,
        final String leaseKey,
        final UUID leaseToken,
        final Duration leaseDuration) {
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(rawPrincipal);
        requireKeysShareSlot(List.of(fenceKey, indexKey, stateKey, leaseKey));
        val duration = requireLeaseDuration(leaseDuration);
        val result = evalInteger(
            ACQUIRE_REBUILD_LEASE_SCRIPT,
            List.of(fenceKey, indexKey, stateKey, leaseKey),
            token(leaseToken),
            ascii(Long.toString(duration.toMillis())),
            ascii(Integer.toString(MAXIMUM_INDEX_ENTRIES)));
        return switch (Math.toIntExact(result)) {
            case -1 -> RebuildLeaseResult.FENCED;
            case 0 -> RebuildLeaseResult.BUSY;
            case 1 -> RebuildLeaseResult.ACQUIRED;
            case 2 -> RebuildLeaseResult.READY;
            case CORRUPT_REDIS_TYPE_RESULT -> throw new IllegalStateException(
                "Account security rebuild lease found corrupt Redis types");
            default -> throw new IllegalStateException("Unexpected account security rebuild-lease result");
        };
    }

    /**
     * Publish a rebuilt index only if the caller still owns its lease.
     *
     * @param rawPrincipal principal
     * @param indexKey index key
     * @param stateKey state key
     * @param leaseKey lease key
     * @param dataKeyPrefix current-format data-key prefix
     * @param leaseToken owner token
     * @return completion result
     */
    public RebuildCompletionResult completeRebuild(
        final String rawPrincipal,
        final String indexKey,
        final String stateKey,
        final String leaseKey,
        final String dataKeyPrefix,
        final UUID leaseToken) {
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(rawPrincipal);
        requireKeysShareSlot(List.of(fenceKey, indexKey, stateKey, leaseKey, dataKeyPrefix));
        for (var attempt = 0; attempt < MAXIMUM_INDEX_RETRIES; attempt++) {
            val snapshot = loadBoundedIndexMembers(fenceKey, indexKey);
            if (snapshot.status() == IndexMemberSnapshotStatus.FENCED) {
                return RebuildCompletionResult.FENCED;
            }
            if (snapshot.status() == IndexMemberSnapshotStatus.CAPACITY_EXCEEDED) {
                return RebuildCompletionResult.CAPACITY_EXCEEDED;
            }
            val keys = explicitAuthorityKeys(
                List.of(fenceKey, indexKey, stateKey, leaseKey),
                dataKeyPrefix,
                snapshot.members());
            val result = evalInteger(
                COMPLETE_REBUILD_SCRIPT,
                keys,
                token(leaseToken),
                key(dataKeyPrefix),
                ascii(Integer.toString(MAXIMUM_INDEX_ENTRIES)));
            switch (Math.toIntExact(result)) {
                case REBUILD_CAPACITY_RESULT -> {
                    return RebuildCompletionResult.CAPACITY_EXCEEDED;
                }
                case -1 -> {
                    return RebuildCompletionResult.FENCED;
                }
                case 0 -> {
                    return RebuildCompletionResult.LEASE_LOST;
                }
                case 1 -> {
                    return RebuildCompletionResult.READY;
                }
                case 2 -> {
                    continue;
                }
                case 3 ->
                    throw new IllegalStateException(
                        "Account security rebuild found a value without a write token");
                case 4 ->
                    throw new IllegalStateException(
                        "Account security rebuild found corrupt Redis types");
                default ->
                    throw new IllegalStateException("Unexpected account security rebuild result");
            }
        }
        throw new ConcurrentModificationException(
            "Account security index changed during rebuild completion");
    }

    /**
     * Release the rebuild lease only when its token still matches.
     *
     * @param leaseKey lease key
     * @param leaseToken owner token
     */
    public void releaseRebuildLease(final String leaseKey, final UUID leaseToken) {
        evalInteger(
            RELEASE_REBUILD_LEASE_SCRIPT,
            List.of(leaseKey),
            token(leaseToken));
    }

    /**
     * Acquire or observe the store-wide schema-adoption lease.
     *
     * @param schemaStateKey schema state key
     * @param schemaLeaseKey schema lease key
     * @param leaseToken owner token
     * @param leaseDuration lease duration
     * @return schema lease result
     */
    public SchemaLeaseResult acquireSchemaLease(
        final String schemaStateKey,
        final String schemaLeaseKey,
        final UUID leaseToken,
        final Duration leaseDuration) {
        requireKeysShareSlot(List.of(schemaStateKey, schemaLeaseKey));
        val duration = requireLeaseDuration(leaseDuration);
        val result = evalInteger(
            ACQUIRE_SCHEMA_LEASE_SCRIPT,
            List.of(schemaStateKey, schemaLeaseKey),
            token(leaseToken),
            ascii(Long.toString(duration.toMillis())));
        return switch (Math.toIntExact(result)) {
            case -1 -> throw new IllegalStateException(
                "Account security schema lease found corrupt Redis types");
            case 0 -> SchemaLeaseResult.BUSY;
            case 1 -> SchemaLeaseResult.ACQUIRED;
            case 2 -> SchemaLeaseResult.READY;
            default -> throw new IllegalStateException(
                "Unexpected account security schema-lease result");
        };
    }

    /**
     * Mark one inventoried principal for lazy same-slot index rebuild.
     *
     * @param rawPrincipal principal
     * @param stateKey principal index-state key
     * @param expiresAt latest known record expiry
     * @return mark result
     */
    public MarkRebuildResult markRebuildRequired(
        final String rawPrincipal,
        final String stateKey,
        final Instant expiresAt) {
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(rawPrincipal);
        requireKeysShareSlot(List.of(fenceKey, stateKey));
        val result = evalInteger(
            MARK_REBUILD_REQUIRED_SCRIPT,
            List.of(fenceKey, stateKey),
            ascii(Long.toString(Objects.requireNonNull(expiresAt, "expiresAt").toEpochMilli())));
        return switch (Math.toIntExact(result)) {
            case CORRUPT_MARK_STATE_RESULT -> throw new IllegalStateException(
                "Account security rebuild mark found corrupt Redis types");
            case -1 -> MarkRebuildResult.FENCED;
            case 0 -> MarkRebuildResult.EXPIRED;
            case 1 -> MarkRebuildResult.MARKED;
            default -> throw new IllegalStateException(
                "Unexpected account security rebuild-mark result");
        };
    }

    /**
     * Mark a principal index as being adopted before an offline schema pass
     * mutates data or membership. The marker is terminal-fence aware and its
     * lifetime covers the latest known record expiry.
     *
     * @param principalDigest validated principal digest
     * @param stateKey principal index-state key
     * @param adoptionToken current schema-adoption owner token
     * @param expiresAt latest known record expiry, or {@code null} for a
     * persistent orphan-state repair marker
     * @return mark result
     */
    public MarkAdoptionResult markAdoptionRequiredByPrincipalDigest(
        final String principalDigest,
        final String stateKey,
        final UUID adoptionToken,
        final Instant expiresAt) {
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKeyForPrincipalDigest(principalDigest);
        requireKeysShareSlot(List.of(fenceKey, stateKey));
        val expiry = expiresAt == null
            ? new byte[0]
            : ascii(Long.toString(expiresAt.toEpochMilli()));
        val result = evalInteger(
            MARK_ADOPTION_REQUIRED_SCRIPT,
            List.of(fenceKey, stateKey),
            expiry,
            token(adoptionToken));
        return switch (Math.toIntExact(result)) {
            case CORRUPT_MARK_STATE_RESULT -> throw new IllegalStateException(
                "Account security adoption mark found corrupt Redis types");
            case -1 -> MarkAdoptionResult.FENCED;
            case 0 -> MarkAdoptionResult.EXPIRED;
            case 1 -> MarkAdoptionResult.MARKED;
            case 2 -> MarkAdoptionResult.READY;
            default -> throw new IllegalStateException(
                "Unexpected account security adoption-mark result");
        };
    }

    /**
     * Validate every adopted index member and publish the exact ready
     * cardinality. This operation is idempotent and scoped to one principal's
     * Redis authority slot.
     *
     * @param principalDigest validated principal digest
     * @param indexKey principal index key
     * @param stateKey principal index-state key
     * @param dataKeyPrefix required current-format data-key prefix
     * @param adoptionToken current schema-adoption owner token
     * @return adoption completion result
     */
    public AdoptionCompletionResult completeAdoptionByPrincipalDigest(
        final String principalDigest,
        final String indexKey,
        final String stateKey,
        final String dataKeyPrefix,
        final UUID adoptionToken) {
        val fenceKey = deletionFence.getKeyCodec().deletionFenceKeyForPrincipalDigest(principalDigest);
        requireKeysShareSlot(List.of(fenceKey, indexKey, stateKey, dataKeyPrefix));
        for (var attempt = 0; attempt < MAXIMUM_INDEX_RETRIES; attempt++) {
            val snapshot = loadBoundedIndexMembers(fenceKey, indexKey);
            if (snapshot.status() == IndexMemberSnapshotStatus.FENCED) {
                return AdoptionCompletionResult.FENCED;
            }
            if (snapshot.status() == IndexMemberSnapshotStatus.CAPACITY_EXCEEDED) {
                return AdoptionCompletionResult.CAPACITY_EXCEEDED;
            }
            val keys = explicitAuthorityKeys(
                List.of(fenceKey, indexKey, stateKey), dataKeyPrefix, snapshot.members());
            val result = evalInteger(
                COMPLETE_ADOPTION_SCRIPT,
                keys,
                key(dataKeyPrefix),
                ascii(Integer.toString(MAXIMUM_INDEX_ENTRIES)),
                token(adoptionToken));
            switch (Math.toIntExact(result)) {
                case REBUILD_CAPACITY_RESULT -> {
                    return AdoptionCompletionResult.CAPACITY_EXCEEDED;
                }
                case -1 -> {
                    return AdoptionCompletionResult.FENCED;
                }
                case 0 -> {
                    return AdoptionCompletionResult.STALE_OWNER;
                }
                case 1 -> {
                    return AdoptionCompletionResult.READY;
                }
                case 2 -> {
                    continue;
                }
                case 3 ->
                    throw new IllegalStateException(
                        "Account security adoption found a value without a write token");
                case 4 -> {
                    return AdoptionCompletionResult.READY;
                }
                case 5 ->
                    throw new IllegalStateException(
                        "Account security adoption found corrupt Redis types");
                default ->
                    throw new IllegalStateException(
                        "Unexpected account security adoption-completion result");
            }
        }
        throw new ConcurrentModificationException(
            "Account security index changed during adoption completion");
    }

    /**
     * Publish completion of store-wide schema adoption.
     *
     * @param schemaStateKey schema state key
     * @param schemaLeaseKey schema lease key
     * @param leaseToken owner token
     * @return true only while the caller owns the lease
     */
    public boolean completeSchemaAdoption(
        final String schemaStateKey,
        final String schemaLeaseKey,
        final UUID leaseToken) {
        requireKeysShareSlot(List.of(schemaStateKey, schemaLeaseKey));
        val result = evalInteger(
            COMPLETE_SCHEMA_SCRIPT,
            List.of(schemaStateKey, schemaLeaseKey),
            token(leaseToken));
        if (result == -1) {
            throw new IllegalStateException(
                "Account security schema completion found corrupt Redis types");
        }
        return result == 1;
    }

    private IndexMemberSnapshot loadBoundedIndexMembers(
        final String fenceKey,
        final String indexKey) {
        requireKeysShareSlot(List.of(fenceKey, indexKey));
        val result = evalMulti(
            BOUNDED_INDEX_MEMBERS_SCRIPT,
            List.of(fenceKey, indexKey),
            ascii(Integer.toString(MAXIMUM_INDEX_ENTRIES)));
        if (result.isEmpty()) {
            throw new IllegalStateException("Redis index snapshot returned no status");
        }
        val status = utf8(result.getFirst());
        if ("CORRUPT".equals(status)) {
            throw new IllegalStateException("Redis index snapshot contains corrupt key types");
        }
        if ("FENCED".equals(status) || "CAPACITY".equals(status)) {
            if (result.size() != 1) {
                throw new IllegalStateException(
                    "Redis index snapshot returned members for a status-only result");
            }
            return new IndexMemberSnapshot(
                "FENCED".equals(status)
                    ? IndexMemberSnapshotStatus.FENCED
                    : IndexMemberSnapshotStatus.CAPACITY_EXCEEDED,
                List.of());
        }
        if (!"MEMBERS".equals(status) || result.size() - 1 > MAXIMUM_INDEX_ENTRIES) {
            throw new IllegalStateException("Redis index snapshot returned an invalid result");
        }
        val members = new LinkedHashSet<String>();
        for (var index = 1; index < result.size(); index++) {
            if (!members.add(deserializeKey(result.get(index)))) {
                throw new IllegalStateException("Redis index snapshot returned a duplicate member");
            }
        }
        return new IndexMemberSnapshot(IndexMemberSnapshotStatus.MEMBERS, List.copyOf(members));
    }

    private static List<String> explicitAuthorityKeys(
        final List<String> baseKeys,
        final String dataKeyPrefix,
        final List<String> members) {
        if (dataKeyPrefix == null || dataKeyPrefix.isBlank()) {
            throw new IllegalArgumentException("Account security data-key prefix is invalid");
        }
        if (baseKeys == null || baseKeys.isEmpty() || members == null) {
            throw new IllegalArgumentException("Account security explicit keys are invalid");
        }
        val uniqueKeys = new LinkedHashSet<String>();
        for (val baseKey : baseKeys) {
            if (baseKey == null || baseKey.isBlank() || !uniqueKeys.add(baseKey)) {
                throw new IllegalArgumentException("Account security base keys are invalid");
            }
        }
        val keys = new ArrayList<String>(baseKeys.size() + members.size() * 2);
        keys.addAll(baseKeys);
        for (val member : members) {
            if (member == null || member.length() <= dataKeyPrefix.length()
                || member.length() > MAXIMUM_DATA_KEY_LENGTH
                || !member.startsWith(dataKeyPrefix)
                || isReservedMemberKey(member)
                || !uniqueKeys.add(member)) {
                throw new IllegalStateException("Account security index contains an invalid member");
            }
            val tokenKey = writeTokenKey(member);
            if (!uniqueKeys.add(tokenKey)) {
                throw new IllegalStateException("Account security index contains aliased members");
            }
            keys.add(member);
            keys.add(tokenKey);
        }
        requireKeysShareSlot(keys);
        return List.copyOf(keys);
    }

    private static boolean isReservedMemberKey(final String member) {
        return member.endsWith(":write-token") || member.endsWith(":revoked");
    }

    private IndexedReadResult<V> readyResult(
        final List<?> result,
        final String dataKeyPrefix) {
        if ((result.size() - 1) % 3 != 0) {
            throw new IllegalStateException("Redis indexed authority returned malformed values");
        }
        val values = new ArrayList<IndexedValue<V>>((result.size() - 1) / 3);
        for (var index = 1; index < result.size(); index += 3) {
            val dataKey = deserializeKey(result.get(index));
            if (!dataKey.startsWith(dataKeyPrefix)
                || !(result.get(index + 1) instanceof final byte[] serializedValue)) {
                throw new IllegalStateException("Redis indexed authority returned an invalid member");
            }
            values.add(new IndexedValue<>(
                dataKey,
                deserializeValue(serializedValue),
                serializedValue,
                writeToken(result.get(index + 2))));
        }
        return new IndexedReadResult<>(IndexedReadStatus.READY, values);
    }

    private static <T> IndexedReadResult<T> statusOnly(
        final List<?> result,
        final IndexedReadStatus status) {
        if (result.size() != 1) {
            throw new IllegalStateException("Redis indexed authority returned values for a status-only result");
        }
        return new IndexedReadResult<>(status, List.of());
    }

    private List<?> evalMulti(
        final byte[] script,
        final List<String> keys,
        final byte[]... arguments) {
        val result = redisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                script,
                ReturnType.MULTI,
                keys.size(),
                keysAndArguments(keys, arguments)));
        return Objects.requireNonNull(result, "indexedAuthorityResult");
    }

    private long evalInteger(
        final byte[] script,
        final List<String> keys,
        final byte[]... arguments) {
        val result = redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                script,
                ReturnType.INTEGER,
                keys.size(),
                keysAndArguments(keys, arguments)));
        if (result == null) {
            throw new IllegalStateException("Redis indexed authority returned no result");
        }
        return result;
    }

    private byte[][] keysAndArguments(final List<String> keys, final byte[][] arguments) {
        val result = new byte[keys.size() + arguments.length][];
        for (var index = 0; index < keys.size(); index++) {
            result[index] = key(keys.get(index));
        }
        System.arraycopy(arguments, 0, result, keys.size(), arguments.length);
        return result;
    }

    private byte[] value(final V value) {
        return Objects.requireNonNull(valueSerializer().serialize(value), "serializedValue");
    }

    private V deserializeValue(final byte[] value) {
        return Objects.requireNonNull(valueSerializer().deserialize(value), "deserializedValue");
    }

    @SuppressWarnings("unchecked")
    private RedisSerializer<V> valueSerializer() {
        return (RedisSerializer<V>) redisTemplate.getValueSerializer();
    }

    @SuppressWarnings("unchecked")
    private byte[] key(final String redisKey) {
        val serializer = (RedisSerializer<String>) redisTemplate.getKeySerializer();
        return Objects.requireNonNull(serializer.serialize(redisKey), "serializedKey");
    }

    @SuppressWarnings("unchecked")
    private String deserializeKey(final Object value) {
        if (!(value instanceof final byte[] bytes)) {
            throw new IllegalStateException("Redis indexed authority returned a non-binary member");
        }
        val serializer = (RedisSerializer<String>) redisTemplate.getKeySerializer();
        return Objects.requireNonNull(serializer.deserialize(bytes), "deserializedKey");
    }

    private static void requireKeysShareSlot(final Collection<String> redisKeys) {
        if (redisKeys == null || redisKeys.size() < 2
            || redisKeys.stream().anyMatch(key -> key == null || key.isBlank())) {
            throw new IllegalArgumentException("Account security indexed keys are invalid");
        }
        val slots = redisKeys.stream()
            .map(RedisAccountSecurityIndexedStore::effectiveHashSlotInput)
            .collect(Collectors.toSet());
        if (slots.size() != 1) {
            throw new IllegalArgumentException("Account security indexed keys do not share one Redis slot");
        }
    }

    private static String effectiveHashSlotInput(final String redisKey) {
        val opening = redisKey.indexOf('{');
        if (opening >= 0) {
            val closing = redisKey.indexOf('}', opening + 1);
            if (closing > opening + 1) {
                return redisKey.substring(opening + 1, closing);
            }
        }
        return redisKey;
    }

    private static Duration requireLeaseDuration(final Duration leaseDuration) {
        val duration = Objects.requireNonNull(leaseDuration, "leaseDuration");
        if (duration.isNegative() || duration.isZero()
            || duration.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("Account security rebuild lease duration is invalid");
        }
        return duration;
    }

    private static byte[] token(final UUID leaseToken) {
        val token = Objects.requireNonNull(leaseToken, "leaseToken");
        if (token.getMostSignificantBits() == 0 && token.getLeastSignificantBits() == 0) {
            throw new IllegalArgumentException("Account security token must not be nil");
        }
        return ascii(token.toString());
    }

    private static UUID writeToken(final Object value) {
        if (!(value instanceof final byte[] bytes)) {
            throw new IllegalStateException("Redis indexed authority returned a non-binary write token");
        }
        val text = new String(bytes, StandardCharsets.US_ASCII);
        try {
            val token = UUID.fromString(text);
            if (!token.toString().equals(text)
                || (token.getMostSignificantBits() == 0 && token.getLeastSignificantBits() == 0)) {
                throw new IllegalArgumentException("non-canonical token");
            }
            return token;
        } catch (final IllegalArgumentException exception) {
            throw new IllegalStateException(
                "Redis indexed authority returned an invalid write token", exception);
        }
    }

    private String terminalFenceKey(final String dataKey) {
        return deletionFence.getKeyCodec().deletionFenceKeyForPrincipalDigest(
            effectiveHashSlotInput(dataKey));
    }

    private static String writeTokenKey(final String dataKey) {
        if (dataKey == null || dataKey.isBlank()) {
            throw new IllegalArgumentException("Account security data key is invalid");
        }
        return dataKey + ":write-token";
    }

    private static void requireRecordRevocationKey(
        final String dataKey,
        final String recordRevocationKey) {
        if (!Objects.equals(dataKey + ":revoked", recordRevocationKey)) {
            throw new IllegalArgumentException(
                "Account security record-revocation key does not match its data key");
        }
    }

    private static byte[] ascii(final String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static String utf8(final Object value) {
        return value instanceof final byte[] bytes
            ? new String(bytes, StandardCharsets.UTF_8)
            : Objects.requireNonNull(value, "indexedAuthorityStatus").toString();
    }

    private static byte[] script(final String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /** Indexed authority read state. */
    public enum IndexedReadStatus {
        /** Index state and values were read atomically. */
        READY,
        /** A bounded one-time index rebuild is required. */
        REBUILD_REQUIRED,
        /** A terminal account-deletion fence rejects the read. */
        FENCED
    }

    /** Indexing outcome for an already-present value. */
    public enum IndexExistingResult {
        /** Value was present and is now indexed. */
        INDEXED,
        /** Value was absent and stale membership is gone. */
        ABSENT,
        /** Exact-record revocation rejects restored authority data. */
        REVOKED,
        /** Terminal fence rejected index mutation. */
        FENCED
    }

    /** Rebuild lease acquisition outcome. */
    public enum RebuildLeaseResult {
        /** Caller owns the rebuild lease. */
        ACQUIRED,
        /** Another caller owns the rebuild lease. */
        BUSY,
        /** Index became ready before a lease was needed. */
        READY,
        /** Terminal fence rejects rebuild. */
        FENCED
    }

    /** Rebuild publication outcome. */
    public enum RebuildCompletionResult {
        /** Rebuilt index is published. */
        READY,
        /** Lease ownership changed before publication. */
        LEASE_LOST,
        /** Terminal fence rejects publication. */
        FENCED,
        /** Principal exceeded the bounded index capacity. */
        CAPACITY_EXCEEDED
    }

    /** Store-wide schema-adoption lease outcome. */
    public enum SchemaLeaseResult {
        /** Caller owns the schema-adoption lease. */
        ACQUIRED,
        /** Another caller owns the schema-adoption lease. */
        BUSY,
        /** Schema adoption is permanently complete. */
        READY
    }

    /** Schema-inventory mark outcome. */
    public enum MarkRebuildResult {
        /** Principal was marked for a bounded rebuild. */
        MARKED,
        /** Terminal deletion fence rejected the marker. */
        FENCED,
        /** Inventoried record had already expired. */
        EXPIRED
    }

    /** Offline schema-adoption marker outcome. */
    public enum MarkAdoptionResult {
        /** Principal was marked for offline adoption. */
        MARKED,
        /** A completed ready state is already monotonic. */
        READY,
        /** Terminal deletion fence rejected the marker. */
        FENCED,
        /** Inventoried record had already expired. */
        EXPIRED
    }

    /** Offline per-principal adoption-completion outcome. */
    public enum AdoptionCompletionResult {
        /** Adopted index is ready. */
        READY,
        /** Terminal deletion fence rejects publication. */
        FENCED,
        /** Per-principal adoption ownership changed before publication. */
        STALE_OWNER,
        /** Principal exceeded the bounded index capacity. */
        CAPACITY_EXCEEDED
    }

    /** Exact-value indexed deletion outcome. */
    public enum CompareAndDeleteIndexedResult {
        /** Expected serialized value matched and was deleted. */
        DELETED,
        /** Value was already absent and stale membership was removed. */
        ABSENT,
        /** Value changed after the authority read. */
        COMPARE_MISMATCH,
        /** A terminal account-deletion fence rejected cleanup. */
        FENCED
    }

    /** Exact-record revocation outcome. */
    public enum RecordRevocationResult {
        /** Exact record was fenced and removed. */
        REVOKED,
        /** Declared record lifetime had already elapsed. */
        EXPIRED,
        /** A permanent terminal fence superseded exact-record revocation. */
        TERMINAL_FENCED
    }

    /** One indexed key, deserialized value, and exact authority bytes. */
    public static final class IndexedValue<T> {
        private final String dataKey;

        private final T value;

        private final byte[] serializedValue;

        private final UUID writeToken;

        private IndexedValue(
            final String dataKey,
            final T value,
            final byte[] serializedValue,
            final UUID writeToken) {
            this.dataKey = Objects.requireNonNull(dataKey, "dataKey");
            this.value = Objects.requireNonNull(value, "value");
            this.serializedValue = Objects.requireNonNull(
                serializedValue, "serializedValue").clone();
            if (this.serializedValue.length == 0) {
                throw new IllegalArgumentException("Indexed serialized value is empty");
            }
            this.writeToken = Objects.requireNonNull(writeToken, "writeToken");
        }

        /**
         * Return the exact Redis data key.
         *
         * @return exact Redis data key
         */
        public String dataKey() {
            return dataKey;
        }

        /**
         * Return the deserialized indexed value.
         *
         * @return deserialized indexed value
         */
        public T value() {
            return value;
        }

        /**
         * Return a defensive copy of the exact serialized authority bytes.
         *
         * @return exact serialized authority bytes
         */
        public byte[] serializedValue() {
            return serializedValue.clone();
        }

        /**
         * Return the exact write token observed with the authority value.
         *
         * @return write token
         */
        public UUID writeToken() {
            return writeToken;
        }
    }

    /** Result of one authority-index read. */
    public record IndexedReadResult<T>(
        IndexedReadStatus status,
        List<IndexedValue<T>> values) {
        public IndexedReadResult {
            Objects.requireNonNull(status, "status");
            values = List.copyOf(Objects.requireNonNull(values, "values"));
        }
    }

    private enum IndexMemberSnapshotStatus {
        MEMBERS,
        FENCED,
        CAPACITY_EXCEEDED
    }

    private record IndexMemberSnapshot(
        IndexMemberSnapshotStatus status,
        List<String> members) {
        private IndexMemberSnapshot {
            Objects.requireNonNull(status, "status");
            members = List.copyOf(Objects.requireNonNull(members, "members"));
        }
    }

    /** Raised when an exact-record revocation fence rejects a delayed writer. */
    public static final class AccountSecurityRecordRevokedException extends IllegalStateException {
        private static final long serialVersionUID = 3536670391923031858L;

        /** Construct the stable revoked-record failure. */
        public AccountSecurityRecordRevokedException() {
            super("Account security record is revoked");
        }
    }

    /** Raised for a known fail-before-write indexed-authority rejection. */
    public static final class AccountSecurityIndexedWriteRejectedException extends IllegalStateException {
        private static final long serialVersionUID = -6484372899552872025L;

        private AccountSecurityIndexedWriteRejectedException(final String message) {
            super(message);
        }
    }
}
