package com.weaponmail.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfig {

    @SuppressWarnings("resource")
    @Bean
    @ServiceConnection
    CassandraContainer scyllaDbContainer() {
        // Vi använder ScyllaDB-image men med Cassandras test-adapter
        return new CassandraContainer(DockerImageName.parse("scylladb/scylla:latest"))
                .withInitScript("scylla.cql"); // Skapa keyspace/tabeller vid start
    }

    @Bean
    @ServiceConnection
    KafkaContainer kafkaContainer() {
        // Kör Kafka i KRaft-läge (ingen Zookeeper behövs!)
        return new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:latest"));
    }
}