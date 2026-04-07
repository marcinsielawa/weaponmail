package com.weaponmail;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.CassandraContainer;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration(proxyBeanMethods = false)
public class TestWeaponMailApplication {

    @Bean
    @ServiceConnection(name = "cassandra")
    CassandraContainer<?> cassandraContainer(){
        return new CassandraContainer<>(DockerImageName.parse("scylladb/scylla:6.0.1"))
            .withInitScript("schema.cql");
    }

    @Bean
    @ServiceConnection(name = "kafka")
    KafkaContainer kafkaContainer() {
        return new KafkaContainer(DockerImageName.parse("apache/kafka:latest"));
    }

    public static void main(String[] args) {
        SpringApplication.from(MessageBackendApplication::main)
            .with(TestWeaponMailApplication.class)
            .run(args);
    }
}