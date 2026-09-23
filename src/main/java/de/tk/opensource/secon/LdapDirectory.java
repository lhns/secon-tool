/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of secon-tool
 * (see https://github.com/DieTechniker/secon-tool).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package de.tk.opensource.secon;

import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

import static javax.naming.directory.SearchControls.OBJECT_SCOPE;
import static javax.naming.directory.SearchControls.ONELEVEL_SCOPE;

/**
 * @author Wolfgang Schmiesing
 * @author Christian Schlichtherle
 */
final class LdapDirectory implements Directory {

    private static final Comparator<X509Certificate> CERTIFICATE_COMPARATOR =
            Comparator.comparing(X509Certificate::getNotAfter);

    private volatile CertificateFactory certificateFactory;

    private final Callable<DirContext> pool;

    LdapDirectory(final Callable<DirContext> pool) {
        this.pool = pool;
    }

    @Override
    public Optional<X509Certificate> certificate(final X509CertSelector selector) throws Exception {
        final String base = String.format("cn=%06X,%s", selector.getSerialNumber(), selector.getIssuerAsString());
        final List<X509Certificate> result = new ArrayList<>();
        final DirContext context = pool.call();
        try (AutoCloseable closeContext = context::close) {
            for (byte[] bytes : search(context, base, "objectClass=pkiUser", OBJECT_SCOPE, byte[].class, "userCertificate;binary")) {
                final X509Certificate cert = certificate(bytes);
                if (selector.match(cert)) {
                    result.add(cert);
                }
            }
        }
        return result.stream().max(CERTIFICATE_COMPARATOR);
    }

    @Override
    public Optional<X509Certificate> certificate(final String identifier) throws Exception {
        final String base = identifier.length() == 9
                ? "ou=IK" + identifier + ",o=LE,c=DE"
                : "ou=BN" + identifier + ",o=AG,c=DE";
        final List<X509Certificate> result = new ArrayList<>();
        final DirContext context = pool.call();
        try (AutoCloseable closeContext = context::close) {
            for (final String dn : search(context, base, "objectClass=*", ONELEVEL_SCOPE, String.class, "seeAlso")) {
                for (byte[] bytes : search(context, dn, "objectClass=pkiUser", OBJECT_SCOPE, byte[].class, "userCertificate;binary")) {
                    result.add(certificate(bytes));
                }
            }
/* Faster alternative for IKs, but doesn't work with all LDAP variants:
            for (byte[] bytes : search(context, "c=de", "sn=IK" + identifier, ONELEVEL_SCOPE, byte[].class, "userCertificate;binary")) {
                result.add(certificate(bytes));
            }
*/
        }
        return result.stream().max(CERTIFICATE_COMPARATOR);
    }

    /**
     * Sucht Einträge unterhalb von {@code base} und gibt die Werte aller angefragten Attribute zurück.
     * Existiert {@code base} nicht, so ist das Ergebnis leer.
     */
    private static <T> List<T> search(
            final DirContext context,
            final String base,
            final String filter,
            final int scope,
            final Class<T> type,
            final String... attrs
    ) throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(scope);
        controls.setReturningAttributes(attrs);
        final List<T> result = new ArrayList<>();
        final NamingEnumeration<SearchResult> results;
        try {
            results = context.search(base, filter, controls);
        } catch (NameNotFoundException ignored) {
            return result;
        }
        try (AutoCloseable closeResults = results::close) {
            // Only the search results are streamed from the server - the attributes and their values of each result
            // are already in memory, so plain enumeration is sufficient for them.
            while (results.hasMore()) {
                for (final Attribute attr : Collections.list(results.next().getAttributes().getAll())) {
                    for (final Object value : Collections.list(attr.getAll())) {
                        result.add(type.cast(value));
                    }
                }
            }
        }
        return result;
    }

    private X509Certificate certificate(byte[] bytes) throws CertificateException {
        return (X509Certificate) certificateFactory().generateCertificate(new ByteArrayInputStream(bytes));
    }

    private CertificateFactory certificateFactory() throws CertificateException {
        final CertificateFactory f = certificateFactory;
        return null != f ? f : (certificateFactory = CertificateFactory.getInstance("X.509"));
    }
}
