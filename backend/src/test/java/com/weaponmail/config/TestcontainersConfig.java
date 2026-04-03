package com.weaponmail.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.containers.wait.strategy.Wait;

import java.time.Duration;

@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfig {

    // ✅ STATIC fält — åtkomligt från @DynamicPropertySource (som är statisk)
    // Testcontainers tilldelar en slumpmässig port på hosten; getBootstrapServers()
    // returnerar "localhost:<random-port>" som Spring sen injicerar.
    static final KafkaContainer kafka =
        new KafkaContainer(DockerImageName.parse("apache/kafka:latest"))
            .withStartupTimeout(Duration.ofSeconds(90));

    static {
        kafka.start(); // starta tidigt, innan Spring context
    }

    // ✅ @DynamicPropertySource är STATISK — kan inte ta bean-parametrar.
    // Vi läser kafka.getBootstrapServers() direkt från det statiska fältet ovan.
    @DynamicPropertySource
    static void overrideKafkaProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        registry.add("weaponmail.kafka.topics.inbox-events", () -> "inbox.events");
    }

    // ✅ Fortfarande en @Bean för att Testcontainers lifecycle-hantering ska funka
    @Bean
    KafkaContainer kafkaContainer() {
        return kafka;
    }

    // ✅ Cassandra med @ServiceConnection — fungerar automatiskt, behöver ingen DynamicPropertySource
    @Bean
    @ServiceConnection
    CassandraContainer scyllaDbContainer() {
        DockerImageName scyllaImage = DockerImageName.parse("scylladb/scylla:latest")
                .asCompatibleSubstituteFor("cassandra");

        return new CassandraContainer(scyllaImage)
                .withStartupTimeout(Duration.ofMinutes(2))
                .withInitScript("schema.cql");
    }
}