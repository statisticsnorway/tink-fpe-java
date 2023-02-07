# Tink FPE Java

Format-Preserving Encryption (FPE) is a type of encryption that encrypts data in a way that preserves the format of the original plaintext. This means that after encryption, the encrypted data retains the same format as the original plaintext, such as a specific length or character set.

## Features

- _Tink FPE_ implements a [Primitive](https://developers.google.com/tink/glossary) that extends the Google Tink framework with support for Format-Preserving Encryption (FPE).
- The following [NIST compliant](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf) algorithms are currently supported: `FF3-1`.
- The implementation of the underlying algorithm is built on top of the excellent [Mysto FPE](https://github.com/mysto/python-fpe) library.
- Tink FPE is currently available for [Python](https://github.com/statisticsnorway/tink-fpe-python) and [Java](https://github.com/statisticsnorway/tink-fpe-java).
- Regarding sensitivity for alphabet, FPE is designed to work with a specific alphabet, which is typically defined in the encryption algorithm. If the plaintext data contains characters that are not part of the defined alphabet, Tink FPE supports different _strategies_ for dealing with the data or substitute the characters with ones that are part of the alphabet.


## Installation

### Maven

```xml
<dependency>
    <groupId>no.ssb.crypto.tink</groupId>
    <artifactId>tink-fpe-java</artifactId>
    <version>[VERSION]</version>
</dependency>
```

### Gradle

```gradle
dependencies {
    implementation 'no.ssb.crypto.tink:tink-fpe-java:VERSION'
}
```

## Usage

// TODO

## Known issues

// TODO: Describe issue about chunking that results in up to last 3 characters not being encrypted.

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [MIT license][license],
_Tink FPE Java_ is free and open source software.

## Issues

If you encounter any problems,
please [file an issue] along with a detailed description.


[file an issue]: https://github.com/statisticsnorway/tink-fpe/issues

<!-- github-only -->

[license]: https://github.com/statisticsnorway/tink-fpe-java/blob/main/LICENSE
[contributor guide]: https://github.com/statisticsnorway/tink-fpe-java/blob/main/CONTRIBUTING.md
