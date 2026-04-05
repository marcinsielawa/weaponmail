package com.weaponmail.account;

import org.springframework.data.cassandra.repository.ReactiveCassandraRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountRepository extends ReactiveCassandraRepository<UserAccount, String> {
    // Inherits: findById(username), save(account), etc.
}