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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Callable;

/**
 * Ein einfacher Speicher im Arbeitsspeicher für Tests.
 * Der Inhalt wird beim Schließen des OutputStreams übernommen.
 */
final class MemoryStore {

    private volatile byte[] content;

    byte[] content() throws FileNotFoundException {
        final byte[] c = content;
        if (null == c) {
            throw new FileNotFoundException("no content");
        }
        return c.clone();
    }

    void content(byte[] content) {
        this.content = content.clone();
    }

    Callable<InputStream> input() {
        return () -> new ByteArrayInputStream(content());
    }

    Callable<OutputStream> output() {
        return () -> new ByteArrayOutputStream() {

            @Override
            public void close() {
                content = toByteArray();
            }
        };
    }
}
