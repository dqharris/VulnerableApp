package org.sasanlabs.configuration;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import java.util.UUID;
import javax.annotation.PostConstruct;
import org.sasanlabs.internal.utility.PasswordHashingUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EmbeddedLDAPConfig {

    // LDAP seed passwords externalized via @Value with environment variable override.
    // Override via LDAP_ALICE_PASSWORD, LDAP_BOB_PASSWORD, etc. in deployment.
    @Value("${ldap.seed.alice.password:#{T(java.util.UUID).randomUUID().toString().substring(0,12)}}")
    private String alicePassword;

    @Value("${ldap.seed.bob.password:#{T(java.util.UUID).randomUUID().toString().substring(0,12)}}")
    private String bobPassword;

    @Value("${ldap.seed.charlie.password:#{T(java.util.UUID).randomUUID().toString().substring(0,12)}}")
    private String charliePassword;

    @Value("${ldap.seed.antriksh.password:#{T(java.util.UUID).randomUUID().toString().substring(0,12)}}")
    private String antrikshPassword;

    private static InMemoryDirectoryServer directoryServer;

    public static InMemoryDirectoryServer getDirectoryServer() {
        return directoryServer;
    }

    @PostConstruct
    public void startLDAPServer() throws Exception {

        InMemoryDirectoryServerConfig config =
                new InMemoryDirectoryServerConfig("dc=sasanlabs,dc=org");

        directoryServer = new InMemoryDirectoryServer(config);

        directoryServer.startListening();

        seedUsers();
    }

    private String createSaltedPassword(String password) {

        String salt = UUID.randomUUID().toString().substring(0, 8);

        String hash = PasswordHashingUtils.sha256Hex(salt, password);

        return salt + ":" + hash;
    }

    private void addUser(String uid, String name, String password) throws Exception {

        String storedPassword = createSaltedPassword(password);

        directoryServer.add(
                "dn: uid=" + uid + ",dc=sasanlabs,dc=org",
                "objectClass: inetOrgPerson",
                "uid: " + uid,
                "sn: " + name,
                "cn: " + name,
                "userPassword: " + storedPassword);
    }

    private void seedUsers() throws Exception {

        directoryServer.add(
                "dn: dc=sasanlabs,dc=org",
                "objectClass: top",
                "objectClass: domain",
                "dc: sasanlabs");

        addUser("alice", "Alice", alicePassword);
        addUser("bob", "Bob", bobPassword);
        addUser("charlie", "Charlie", charliePassword);
        addUser("antriksh", "Antriksh", antrikshPassword);

        for (int i = 5; i <= 10; i++) {
            // Generate unique passwords for generic users
            String userPassword = UUID.randomUUID().toString().substring(0, 12);
            addUser("user" + i, "User " + i, userPassword);
        }
    }
}
