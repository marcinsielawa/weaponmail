package com.weaponmail;

import com.weaponmail.config.TestcontainersConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Import(TestcontainersConfig.class) // Importera våra containers
class WeaponMailApplicationTests {

    @Test
    void contextLoads() {
        // Om detta test passerar, betyder det att ScyllaDB och Kafka 
        // har startat i Docker och att Spring WebFlux har kopplat upp sig!
        System.out.println("Systemet är redo för utveckling!");
    }
}