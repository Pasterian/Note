# Note

# SBOM Analysis

“Establishing a reliable SBOM Toolset”

 

We all sit somewhere in the software development supply chain SDLC, most in the middle, some right on the bleeding edge, others on the outer most nodes. No matter where our positions align, we all inherit from an upstream supplier. We are then responsible for guiding our product neatly within the bounds of the Customer’s strict requirements. 

In order to coordinate our track within these bounds, we need to be able to accurately describe in great fidelity every aspect and component of the product, from it’s atomic utility classes to it’s assembled final form.  

Software Bill of materials (or SBOM) is a vital process in the SDLC. It allows us break down a package into it’s most granular parts and perform analysis on resources and dependencies the product is currently comprised of. Documenting and reporting of SBOMs is essential and is widely used in industry.

To achieve supply chain security at scale, software engineering leaders can mitigate security and licensing compliance risks by integrating SBOMs into their pipelines. This means accomplishing the following:

- Automatically generate SBOMs for all software produced
- Automatically verify SBOMs for software consumed (both open source and proprietary)
- Use SBOM data to continuously assess security and compliance risks (before and after deployment)

An SBOM can provide a comprehensive view of the software composition, aiding in:

1. **Security Analysis:** Identifying and addressing security vulnerabilities in the dependencies.
2. **License Compliance:** Ensuring that the project complies with the licenses associated with each dependency.
3. **Traceability:** Understanding the relationships and interdependencies between different components.
4. **Risk Management:** Assessing and mitigating risks associated with the software components used.

## OWASP’s Open Source Policy on Artefacts

Open source policies provide guidance and governance to organizations looking to reduce third-party and open source risk. Policies typically include:

- Restrictions on component age
- Restrictions on outdated and EOL/EOS components
- Prohibition of components with known vulnerabilities
- Restrictions on public repository usage
- Restrictions on acceptable licenses
- Component update requirements
- Deny list of prohibited components and versions
- Acceptable community contribution guidelines

Full List Here 

https://owasp.org/www-community/Component_Analysis#tools-listing

“”

My current theory on this, awaiting a bit more use in anger, with a 
simple custom REST API integration between our dev tools and 
DependencyTrack. I do appreciate ideas for enhancement or improvement.

- Continuous Assurance Monitoring via OWASP DependencyTrack
- Generate SBOMs with cdxgen
- Produce SBOM artefact with build
- on deployment submit SBOM for project with version representing the environment it is running in.
- these would be the highest priority for monitoring and tracking state, this SBOM is a currently executing environment
- on Pull Request, produce SBOM for build, send to DependencyTrack
using PR# as the version number, wait for results, submit
DependencyTrack findings as Pull Request comments, fail build as
necessary
- Walk your code repository tool, clone latest master/main, generate SBOM, submit to DTrack

“”

“”

Trivy, as others have mentioned, is probably as safe bet at the moment. Good accuracy with support for a lot of ecosystems, including container images.

SBOMS are already pretty much standardized at this point, with CycloneDX and SPDX being the main formats. This makes it easy to use combine a few tools (SCA, storage, analysis etc) to a working stack.

The tricky problem at the moment is to continuously monitor and track the relevance of SBOMs over time (i.e. What is actually running in production?), and how to actually work with any findings. This is where ex. DependencyTrack falls apart pretty quick IMHO.

“”

### Minimal SBOM Content

An SBOM’s minimal viable content is described as containing a component name, version and license. The challenge lies in expressing as much data as possible without redundacy of data.

| Component Name | Supplier Name | Version | Author | Hash | UID | Relationship | License | Release Date | Source URL |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Express | Node.js Foundation | 4.17 | Express.js Team | sha256... | abcdef-123456 | Depends On | MIT | 2023-01-15 | https://github.com/abc/library-a |
| Axios | Axios | 5.4.1 | Matt Zabriskie | sha256... | ghijk-789012 | Used By | Apache-2.0 | 2023-02-28 | https://github.com/xyz/library-b |
| BCrypt.js | BCrypt.js | 12.2.8 | Olivier Poitrey | sha256... | lmno-345678 | Incorporates | Proprietary | 2023-03-10 | https://github.com/mycompany/app |

 SBOMs are commonly expressed in either one of these standards

| SBOM Format | Tools | Description |
| --- | --- | --- |
| CycloneDX | https://cyclonedx.org/tool-center/ | An open standard widely adopted format with flexible granularity |
| SPDX - Software Identification Tags | •  https://spdx.dev/tools-community/
•  https://spdx.dev/tools-commercial/ | SPDP, a comprehensive standard of documenting components |
| SWID - Software Identification Tags | https://pages.nist.gov/swid-tools/ | Swid tags uniquely identify components |
| JSON / XML | https://www.w3.org/TR/json-ld11/

OMG XML Specification | Flexible |

### CycloneDX

```jsx
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.3",
  "metadata": {
    "timestamp": "2023-11-16T12:00:00Z",
    "tool": {
      "vendor": "ExampleCorp",
      "name": "BOMGenerator",
      "version": "2.1"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:github/intelinked/component-a@1.2.3",
      "group": "com.intelinked",
      "name": "component-a",
      "version": "1.2.3",
      "purl": "pkg:github/intelinked/component-a@1.2.3",
      "licenses": [
        {
          "license": "MIT"
        }
      ]
    },
    // ... (similar entries for other components)
  ]
}
```

### SPDX

```jsx
{
  "SPDXVersion": "SPDX-2.2",
  "dataLicense": "CC0-1.0",
  "packages": [
    {
      "name": "InteLinked",
      "version": "1.0",
      "filesAnalyzed": true,
      "licenseDeclared": "Apache-2.0",
      "licenseInfoFromFiles": ["LICENSE.txt"],
      "files": [
        {
          "fileName": "component-a.jar",
          "licenseConcluded": "MIT"
        },
        // ... (similar entries for other components)
      ]
    }
  ]
}
```

### SWID

```jsx
<?xml version="1.0" encoding="UTF-8"?>
<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
                  xmlns:swid="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
                  swid:lang="en">
  <Name>InteLinked</Name>
  <Version>1.0</Version>
  <Entity>
    <Name>component-a</Name>
    <Version>1.2.3</Version>
    <Regid>pkg:github/intelinked/component-a@1.2.3</Regid>
    <TagId>component-a</TagId>
    <Thumbprint algorithm="sha-256">abc123...</Thumbprint>
    <SoftwareCreator>
      <Name>ExampleCorp</Name>
    </SoftwareCreator>
    <SoftwareLicensor>
      <Name>MIT</Name>
    </SoftwareLicensor>
  </Entity>
  <!-- ... (similar entries for other components) -->
</SoftwareIdentity>
```

---

### JSON

```jsx
{
  "InteLinked": {
    "version": "1.0",
    "components": [
      {
        "name": "component-a",
        "version": "1.2.3",
        "license": "MIT",
        "url": "https://github.com/intelinked/component-a"
      },
      // ... (similar entries for other components)
    ]
  }
}
```

### Taxonomy of Tooling

| Category | Type | Description |
| --- | --- | --- |
| During Build | Build  | Document is automatically created as an artifact containing information about the build |
| After Build | Audit Tool | Source Code analysis is performed  |
| Parse | View | must be able to be understood in a human readable format (graph, image, tables, text) |
|  | Difference | Be able to compare compare 2 or files to determine differences in SBOMS |
|  | Analyse | To be able to import BOM file to be analysed  |
| Transform | Translate | Be able to convert one file type to another whilst ensuring no loss of data |
|  | Merge | Be able to merge multiple files for audit and analysis    |
|  | Tooling Integration | Ensure output can be used in other tooling where needed |

Tools 

Quick Overview

| Name |  |
| --- | --- |
| Taxonomy |  |
| Functionality |  |
| Website |  |
| Install Instructions |  |
| How To Guide |  |
| Standards Supported |  |

## cdxgen

| cdxgen | Consume (View), Consume (Diff), Parse (Analyze), Transform (Translate), Transform (Merge) |
| --- | --- |
| Functionality | cdxgen is a CLI tool, library, https://github.com/CycloneDX/cdxgen/blob/master/ADVANCED.md, and server to create a valid and compliant https://cyclonedx.org/ |
| Website | Website: https://github.com/CycloneDX/cdxgen |
| Installation instructions | https://github.com/CycloneDX/cdxgen#installing |
| How to Guide | https://github.com/CycloneDX/cdxgen#usage |
| Supported Standards | CycloneDX,  |
| Offline Support | Yes |

**Overview:**
Cdxgen is a versatile CycloneDX Generator, serving as both a polyglot tool and a library for seamlessly generating various Bill of Materials (BOM) in CycloneDX specifications. Designed to simplify SBOM creation, Cdxgen streamlines the process for applications and container images, providing a unified solution for DevSecOps workflows.

**Key Features:**

- **Polyglot Capability:** Cdxgen supports multiple languages and platforms, ensuring compatibility with a diverse range of applications, including Node.js, Java, PHP, Python, Go, Ruby, Rust, .Net, Docker, and more.
- **CI/CD Integration:** Seamlessly integrates into CI/CD pipelines, automating the generation of Software Bill of Materials (SBOM) for thorough security analysis.
- **Dependency Track Integration:** Automatically submits the generated BOM to the Dependency Track server, facilitating centralized analysis and tracking of dependencies.

**Use Cases:**

- **Comprehensive SBOM Generation:** Suited for organizations relying on diverse languages and platforms, Cdxgen provides a one-stop solution for generating Software and Operations Bill of Materials.
- **DevSecOps Integration:** Integrates seamlessly into CI/CD pipelines, ensuring continuous security checks for containerized applications and diverse software projects.
- **Dependency Track Analysis:** Facilitates efficient tracking and analysis of dependencies by automatically submitting generated BOMs to Dependency Track.

**Supported Languages and Platforms:**

Cdxgen supports a wide array of languages and platforms, including Node.js, Java, PHP, Python, Go, Ruby, Rust, .Net, Docker, and more. It covers various package formats, transitive dependencies, and evidence for different ecosystems.

**Advanced Usage:**

Cdxgen goes beyond basic usage, offering advanced capabilities as a library and in REPL mode. It supports SBOM signing and provides an option to query public registries for package licenses.

**Notes and Requirements:**

- Specific requirements are outlined for different languages and platforms, ensuring proper parsing and generation of SBOMs.
- Advanced usage includes considerations such as SBOM signing and the option to fetch license information from public registries.

If you have any specific questions or need further details, feel free to ask!

### Trivy

| Trivy Support | Consume (View), Consume (Diff), Parse (Analyze), Transform (Translate), Transform (Merge) |
| --- | --- |
| Functionality | Trivy is a comprehensive container image scanner that not only identifies vulnerabilities but also provides detailed information about packages and their versions. It supports multiple vulnerability databases and is capable of outputting results in various formats. |
| Website | Website: https://aquasecurity.github.io/trivy/ |
| Installation instructions | https://aquasecurity.github.io/trivy/v0.21.0/getting-started/installation.html |
| How to Guide | https://aquasecurity.github.io/trivy/v0.21.0/getting-started/basic-usage.html |
| Supported Standards | NVD, Red Hat, Ubuntu, Alpine, Amazon Linux, Oracle Linux, Debian, Suse, Photon OS |
| Offline Support | Yes - See `trivy --download-db` |

**Overview:**
Trivy is a container image scanner and a static analysis tool for vulnerabilities in containerized environments. It focuses on identifying security issues within container images and is widely used in DevSecOps workflows. Trivy supports various image formats, making it a popular choice for securing containerized applications.

**Key Features:**

- **Compatibility:** Tailored for containerized environments, supporting Docker and OCI image formats.
- **Offline Mode:** Operates in offline mode using an offline vulnerability database.
- **Additional Features:**
    - Fast and efficient scanning.
    - Support for multiple vulnerability databases (NVD, Red Hat, Ubuntu, etc.).

**Use Cases:**

- Suited for organizations heavily relying on containerized deployments.
- Integrates seamlessly into CI/CD pipelines for continuous security checks.

### CycloneDX

**Overview:**
CycloneDX is an open standard designed for creating lightweight SBOMs for use in application security contexts and supply chain component analysis. It provides a common format for documenting the components used in software projects and the relationships between them. CycloneDX is language-agnostic and can be easily integrated into various build processes.

**Key Features:**

- **Compatibility:** Supports multiple programming languages and ecosystems.
- **Offline Mode:** Allows for the generation and consumption of SBOMs in offline environments.
- **Additional Features:**
    - Versioning information for components.
    - Vulnerability reporting.
    - Support for SPDX license identifiers.

**Use Cases:**

- Versatile tool suitable for projects with diverse technology stacks.
- Ideal for organizations that require offline SBOM generation capabilities.

### Syft

| Syft Support | Consume (View), Consume (Diff), Parse (Analyze), Transform (Translate), Transform (Merge), Tooling Integration |
| --- | --- |
| Functionality | Syft focuses on deep inspection of container images, offering analysis and reporting on dependencies, licenses, and vulnerabilities. It integrates well with other tooling and provides comprehensive insights into container image composition. |
| Website | Website: https://anchore.com/syft/ |
| Installation instructions | https://github.com/anchore/syft#installation |
| How to Guide | https://github.com/anchore/syft#usage |
| Supported Standards | SPDX |
| Offline Support | Yes |

**Overview:**
Syft is an open-source tool for generating SBOMs for container images. It performs deep inspection and analysis of container images to provide detailed information about their composition. Syft aims to enhance transparency and security in containerized environments by reporting on dependencies, licenses, and vulnerabilities.

**Key Features:**

- **Compatibility:** Well-suited for containerized applications and images.
- **Offline Mode:** Supports offline mode by utilizing locally stored image layers.
- **Additional Features:**
    - Deep inspection capabilities.
    - Comprehensive reporting on dependencies and licenses.

**Use Cases:**

- Suitable for organizations adopting containerization technologies.
- Provides detailed insights into container image composition for security and compliance.

### Grype

| Grype Support | Consume (View), Consume (Diff), Parse (Analyze), Transform (Translate), Transform (Merge), Tooling Integration |
| --- | --- |
| Functionality | Grype is a vulnerability scanner for container images, emphasizing simplicity and ease of integration. It supports viewing, diffing, and analyzing SBOMs, making it a versatile tool in container security workflows. |
| Website | Website: https://github.com/anchore/grype |
| Installation instructions | https://github.com/anchore/grype#installation |
| How to Guide | https://github.com/anchore/grype#usage |
| Supported Standards | SPDX |
| Offline Support | Yes |

**Overview:**
Grype is a vulnerability scanner for container images, focusing on simplicity and ease of integration. It is designed to identify vulnerabilities in containerized environments efficiently. Grype is part of the Anchore Engine project and aims to provide a straightforward yet effective solution for securing container images.

**Key Features:**

- **Compatibility:** Tailored for containerized environments, supporting Docker and OCI formats.
- **Offline Mode:** Supports offline scanning using a local vulnerability database.
- **Additional Features:**
    - Emphasis on simplicity and ease of integration.
    - Utilizes a local vulnerability database.

**Use Cases:**

- Ideal for organizations seeking straightforward container security.
- Fits well into CI/CD pipelines with minimal setup and configuration.

### Safety

| Safety Support | Consume (View), Consume (Diff), Parse (Analyze), Tooling Integration |
| --- | --- |
| Functionality | Safety is a lightweight Python-specific security tool that checks installed dependencies for known vulnerabilities. It operates as an audit tool for Python projects. |
| Website | Website: https://pyup.io/safety/ |
| Installation instructions | https://pyup.io/safety/docs/ |
| How to Guide | https://pyup.io/safety/docs/ |
| Supported Standards | N/A |
| Offline Support | Yes |

**Overview:**
Safety is a lightweight Python-specific security tool designed to identify known security vulnerabilities in Python dependencies. It operates as an audit tool, providing a quick and simple way to enhance the security of Python projects by checking for potential issues in the installed packages.

**Key Features:**

- **Compatibility:** Specifically designed for Python packages.
- **Offline Mode:** Can operate in offline mode using locally stored vulnerability databases.
- **Additional Features:**
    - Lightweight and focused on Python projects.

**Use Cases:**

- Suitable for organizations with Python-centric development.
- Provides a simple and quick way to enhance Python package security.

### Sonatype Nexus IQ

| Nexus IQ Support | Consume (View), Consume (Diff), Parse (Analyze), Transform (Translate), Transform (Merge), Tooling Integration |
| --- | --- |
| Functionality | Sonatype Nexus IQ is a comprehensive platform providing component intelligence, policy management, and continuous monitoring. It supports various SBOM-related functions and integrates well with other tooling in the software supply chain. |
| Website | Website: https://www.sonatype.com/nexus/iq-server |
| Installation instructions | https://help.sonatype.com/iqserver/installation |
| How to Guide | https://help.sonatype.com/iqserver/overview |
| Supported Standards | N/A |
| Offline Support | Yes |

**Overview:**
Sonatype Nexus IQ is a comprehensive platform for managing and securing open-source components. It is not just an SBOM tool but a broader solution for component intelligence, policy management, and continuous monitoring. Nexus IQ supports multiple ecosystems, including Java, .NET, npm, and more.

**Key Features:**

- **Compatibility:** Supports a wide range of ecosystems and technologies.
- **Offline Mode:** Facilitates offline scans by allowing users to import data feeds.
- **Additional Features:**
    - Advanced policy management.
    - Continuous monitoring.
    - Remediation guidance for vulnerabilities.

**Use Cases:**

- Ideal for enterprises with diverse technology stacks.
- Suited for organizations requiring advanced policy management, continuous monitoring, and comprehensive remediation guidance.

## Conclusion

All of the tools mentioned above have their rightful usages, as SBOMS are already pretty much standardized at this point, with CycloneDX and SPDX being the main formats. This makes it easy to use combine a few tools (SCA, storage, analysis etc) to a working stack.

Choosing a combination of tools, specifically cdxgen for versatile SBOM creation and Trivy for comprehensive container image scanning, is recommended. Trivy's support for air-gapped environments adds an additional layer of security. Following the outlined process ensures a robust and secure software supply chain. Regular reviews, feedback seeking, and adaptation based on evolving needs will contribute to continuous improvement in both DependencyTrack and Trivy integration.

1. **SBOM Generation and Submission:**
    - Use cdxgen to create SBOMs during builds.
    - Submit SBOMs on deployment, representing the environment.
    - Utilize Trivy for comprehensive sbom/container image scanning during builds and deployments.
2. **Continuous Monitoring:**
    - Prioritize monitoring for deployed environments.
    - Regularly submit SBOMs and Trivy scan results for ongoing monitoring.
3. **Pull Request Integration:**
    - Produce SBOM for PR builds using the PR number as version.
    - Utilize Trivy to perform container image scanning for PR builds.
    - Send SBOM and Trivy findings to DependencyTrack.
    - Comment on PR with DependencyTrack findings and fail the build if needed.
4. **Optional Team Integration:**
    - Integrate DependencyTrack for teams that version but don't build.
    - Use Trivy for periodic container image scanning in non-build scenarios.
5. **Automation and Customization:**
    - Fully automate the process within the CI/CD pipeline.
    - Set custom security policies and notifications in both DependencyTrack and Trivy.
6. **Versioning and Logging:**
    - Maintain a clear versioning strategy for both SBOMs and Trivy scan results.
    - Implement logging for transparency and troubleshooting in both DependencyTrack and Trivy.
7. **Pipeline Orchestration:**
    - Use pipeline orchestration tools for management and traceability of both SBOMs and Trivy scan results.
8. **Review and Adaptation:**
    - Regularly review DependencyTrack metrics for SBOMs and Trivy scan results.
    - Seek feedback for continuous improvement in both DependencyTrack and Trivy.
    - Adapt the process based on evolving needs for both SBOMs and Trivy scan results.

## Utilities

### FOSSology

| Support | Produce(Analyze), Produce(Manual), Consume(View), Consume(Diff), Consume(Analyze), Transform(Translate), Transform(Merge), Transform(Tool Support) |
| --- | --- |
| Functionality | FOSSology is an open source license compliance software system and toolkit allowing users to run license, copyright and export control scans from a REST API. 
As a system, a database and web UI are provided to provide a compliance workflow.
As part of the toolkit multiple license scanners, copyright and export scanners are tools available to help with compliance activities. |
| Location | Website: https://www.fossology.org/
Source: https://github.com/fossology |
| Installation instructions | https://www.fossology.org/get-started/ |
| How to use | https://www.fossology.org/get-started/basic-workflow/ |
| versions supported: | SPDX 2.1, SPDX 2.2 |

FOSSology is an open source license compliance software system and toolkit. As a toolkit, you can run license, copyright, and export control scans from the command line. As a system, a database and web UI are provided to give you a compliance workflow. In one click you can generate an SPDX file or a ReadMe with all the copyrights notices from your software. FOSSology deduplication means that you can scan an entire distro, rescan a new version, and only the changed files will get rescanned. This is a big time saver for large projects.

### CycloneDX for Rust

| CycloneDX Support | Transform (Tool support) |
| --- | --- |
| Functionality | Library that supports object models, serialization and deserialization of CycloneDX SBOMs. |
| Location | Website: https://github.com/doddi/cyclonedx-rust
Source: https://github.com/doddi/cyclonedx-rust |
| Installation instructions | See https://github.com/doddi/cyclonedx-rust |
| How to use |  |

### CycloneDX for Rust Cargo

| CycloneDX Support | Produce (Build) |
| --- | --- |
| Functionality | Creates CycloneDX SBOMs for Rust Cargo projects |
| Location | Website: https://crates.io/crates/cyclonedx-bom
Source: https://github.com/CycloneDX/cyclonedx-rust-cargo |
| Installation instructions | cargo install cyclonedx-bom |
| How to use | ~/.cargo/bin/cyclonedx-bom cyclonedx |

## SPDX

### bom

| Support | Produce (Build, Analyze) Consume (View), Transform(Tools Support) |
| --- | --- |
| Functionality | bom is the SBOM tool written by the kubernetes community to generate the bill of materials of kubernetes releases. The tool is used by several cloud native projects to generate their SBOMs.
Bom can generate sbom through analysis of several sources. Supports output in TAGtag-value format and JSON. It also supports visualization and querying of documents. |
| Location | Website:https://github.com/kubernetes-sigs/bom
Source: https://github.com/kubernetes-sigs/bom |
| Installation instructions | https://github.com/kubernetes-sigs/bom#installation |
| How to use | https://github.com/kubernetes-sigs/bom/blob/main/docs/create-a-bill-of-materials.md |
| versions supported: | SPDX 2.3 |
| Types | Source, Build |
| Logo | https://github.com/kubernetes-sigs/bom/blob/main/logo/logo.png |

### SPDX Java Libraries and Tools