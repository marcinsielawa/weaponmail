package com.weaponmail.message;

import org.springframework.data.cassandra.core.cql.Ordering;
import org.springframework.data.cassandra.core.cql.PrimaryKeyType;
import org.springframework.data.cassandra.core.mapping.PrimaryKeyClass;
import org.springframework.data.cassandra.core.mapping.PrimaryKeyColumn;
import java.io.Serializable;
import java.util.UUID;

@PrimaryKeyClass
public record MessageKey(
    @PrimaryKeyColumn(name = "recipient", ordinal = 0, type = PrimaryKeyType.PARTITIONED)
    String recipient,

    @PrimaryKeyColumn(name = "thread_id", ordinal = 1, type = PrimaryKeyType.CLUSTERED)
    UUID threadId,

    @PrimaryKeyColumn(name = "id", ordinal = 2, type = PrimaryKeyType.CLUSTERED, ordering = Ordering.DESCENDING)
    UUID id
) implements Serializable {}