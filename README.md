## apache-jdkim  [![Build Status](https://travis-ci.org/Bedework/apache-jdkim.svg)](https://travis-ci.org/Bedework/apache-jdkim)

This project is a fork of the Apache jdkim project for
[Bedework](https://www.apereo.org/projects/bedework).

These classes implement a version if DKIM for iSchedule. This is still
experimental and may never come to full production. If and when it does
we can possibly merge back to the main project.

### Requirements

1. JDK 7
2. Maven 3

### Building Locally

> mvn clean install

### Releasing

Releases of this fork are published to Maven Central via Sonatype.

To create a release, you must have:

1. Permissions to publish to the `org.bedework` groupId.
2. `gpg` installed with a published key (release artifacts are signed).

To perform a new release:

> mvn release:clean release:prepare

When prompted, select the desired version; accept the defaults for scm tag and next development version.
When the build completes, and the changes are committed and pushed successfully, execute:

> mvn release:perform

For full details, see [Sonatype's documentation for using Maven to publish releases](http://central.sonatype.org/pages/apache-maven.html).
