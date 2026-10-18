// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

package demo;

/**
 * Trivial library entry point. The javadoc here exists so the
 * maven-javadoc-plugin run has something non-empty to package.
 */
public final class Lib {
    private Lib() {}

    /** Returns the canonical demo greeting. */
    public static String greet() {
        return "hello";
    }
}
