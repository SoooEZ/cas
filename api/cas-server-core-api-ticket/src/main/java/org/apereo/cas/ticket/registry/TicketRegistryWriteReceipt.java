package org.apereo.cas.ticket.registry;

import module java.base;

/**
 * Immutable resource-side acknowledgement for one ticket-registry write.
 *
 * <p>A positive sequence is allocated by the authoritative storage resource in
 * the same atomic operation as the ticket write. Zero values explicitly mean
 * that the default registry path supplied no fencing evidence; security
 * interceptors may reject such a completion. Receipts never contain a raw
 * ticket identifier.</p>
 *
 * @author SoooEZ
 * @param storeName canonical persistence store name
 * @param writeSequence resource-local monotonic sequence, or zero when absent
 * @param projectionRevision generation projection revision, or zero when absent
 * @param replay whether the resource proved an exact idempotent replay
 * @since 8.0.0
 */
public record TicketRegistryWriteReceipt(
    String storeName,
    long writeSequence,
    long projectionRevision,
    boolean replay) implements Serializable {

    private static final int MAXIMUM_STORE_NAME_LENGTH = 64;

    @Serial
    private static final long serialVersionUID = -7560635135130984156L;

    public TicketRegistryWriteReceipt {
        storeName = Objects.requireNonNull(storeName, "storeName").trim();
        if (storeName.isEmpty() || storeName.length() > MAXIMUM_STORE_NAME_LENGTH) {
            throw new IllegalArgumentException("Ticket store name is not canonical");
        }
        if (writeSequence < 0 || projectionRevision < 0) {
            throw new IllegalArgumentException("Ticket write receipt values cannot be negative");
        }
        if ((writeSequence == 0) != (projectionRevision == 0)) {
            throw new IllegalArgumentException(
                "Ticket write sequence and projection revision must both be present or absent");
        }
        if (replay && writeSequence == 0) {
            throw new IllegalArgumentException("An unsequenced ticket write cannot prove replay");
        }
    }

    /**
     * Create an explicit receipt for the backwards-compatible unfenced path.
     *
     * @param storeName persistence store name
     * @return unsequenced receipt
     */
    public static TicketRegistryWriteReceipt unsequenced(final String storeName) {
        return new TicketRegistryWriteReceipt(storeName, 0, 0, false);
    }

    /** Whether the storage resource supplied strict fencing evidence. */
    public boolean isSequenced() {
        return writeSequence > 0 && projectionRevision > 0;
    }
}
