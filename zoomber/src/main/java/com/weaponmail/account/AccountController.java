package com.weaponmail.account;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> signUp(@RequestBody UserAccount account) {
        return accountService.signUp(account);
    }

    @PostMapping("/login")
    public Mono<AuthResponse> login(@RequestBody LoginRequest login) {
        return accountService.login(login.username, login.loginHash);
    }

    @PostMapping("/logout")
    public Mono<Void> logout(@RequestHeader("Authorization") String token) {
        return accountService.logout(token.replace("Bearer ", ""));
    }

    /**
     * Public key lookup — used by senders before composing a message.
     * Returns ONLY the public key; no private material ever leaves the server.
     */
    @GetMapping("/{username}/public-key")
    public Mono<PublicKeyResponse> getPublicKey(@PathVariable String username) {
        return accountService.getPublicKey(username)
                .map(key -> new PublicKeyResponse(username, key));
    }
}