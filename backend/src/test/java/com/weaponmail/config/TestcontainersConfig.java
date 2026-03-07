package com.weaponmail.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfig {

    @SuppressWarnings("resource")
    @Bean
    CassandraContainer scyllaDbContainer() {
        // Fix för ScyllaDB-kompatibilitet
        DockerImageName scyllaImage = DockerImageName.parse("scylladb/scylla:latest")
                .asCompatibleSubstituteFor("cassandra");
        
        return new CassandraContainer(scyllaImage)
                .withInitScript("schema.cql");
    }

    @SuppressWarnings("resource")
    @Bean
    KafkaContainer kafkaContainer() {
        // Vi kör på latest men lagar start-skriptet manuellt
        return new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:latest")
                .asCompatibleSubstituteFor("apache/kafka"))
                .withCreateContainerCmdModifier(cmd -> {
                    // Vi "lurar" Testcontainers genom att länka det nya skriptet till det gamla stället
                    cmd.withEntrypoint("sh", "-c", 
                        "mkdir -p /etc/kafka/docker && ln -s /etc/confluent/docker/run /etc/kafka/docker/run && exec /etc/confluent/docker/run");
                });
    }

    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry registry, 
                             KafkaContainer kafka, 
                             CassandraContainer scylla) {
        
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        
        registry.add("spring.cassandra.contact-points", () -> 
            scylla.getHost() + ":" + scylla.getMappedPort(9042));
        registry.add("spring.cassandra.local-datacenter", () -> "datacenter1");
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
    }
}