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
                .withInitScript("schema.cql"); // Skapar tabellerna från main/resources
    }

    @SuppressWarnings("resource")
    @Bean
    KafkaContainer kafkaContainer() {
        // Fix för Kafka latest + KRaft (utan Zookeeper)
        return new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:latest")
                .asCompatibleSubstituteFor("apache/kafka"))
                .withCreateContainerCmdModifier(cmd -> {
                    // Vi "lurar" Testcontainers genom att länka det nya skriptet till det gamla stället
                    cmd.withEntrypoint("sh", "-c", 
                        "mkdir -p /etc/kafka/docker && ln -s /etc/confluent/docker/run /etc/kafka/docker/run && exec /etc/confluent/docker/run");
                })               
                // Vi lägger till dessa för att slippa "advertised.listeners must not be empty"
                .withEnv("KAFKA_NODE_ID", "1")
                .withEnv("KAFKA_PROCESS_ROLES", "broker,controller")
                .withEnv("KAFKA_CONTROLLER_QUORUM_VOTERS", "1@kafka:9093")
                .withEnv("KAFKA_LISTENERS", "PLAINTEXT://kafka:29092,PLAINTEXT_HOST://kafka:9092,CONTROLLER://kafka:9093")
                .withEnv("KAFKA_ADVERTISED_LISTENERS", "PLAINTEXT://kafka:29092,PLAINTEXT_HOST://localhost:9092")
                .withEnv("KAFKA_CONTROLLER_LISTENER_NAMES", "CONTROLLER")
                .withEnv("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", "PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT,CONTROLLER:PLAINTEXT")
                .withEnv("KAFKA_INTER_BROKER_LISTENER_NAME", "PLAINTEXT")
                .withEnv("KAFKA_AUTO_CREATE_TOPICS_ENABLE", "true")
                .withEnv("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR", "1")
                .withEnv("KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR", "1")
                .withEnv("KAFKA_TRANSACTION_STATE_LOG_MIN_ISR", "1")
                .withEnv("KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS", "0")
                .withEnv("CLUSTER_ID", "MkU3OEVBNTcwNTJENDM2Qk");
        
        
    }

    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry registry, 
                             KafkaContainer kafka, 
                             CassandraContainer scylla) {
        
        // Synka med main/resources/application.yml
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        
        registry.add("spring.cassandra.contact-points", () -> 
            scylla.getHost() + ":" + scylla.getMappedPort(9042));
        registry.add("spring.cassandra.local-datacenter", () -> "datacenter1");
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
        
        // Om du har topics i main config kan vi säkerställa att de används här också
        registry.add("weaponmail.kafka.topics.inbox-events", () -> "inbox.events");
    }
}