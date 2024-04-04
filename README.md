# semgrep-rules
## Table of Contents

[Setup](#Setup)

 - [Semgrep Installation](#Semgrep-Installation)

 - [Steps for Project Setup](#Steps-for-Project-Setup)
 
 [Creating SAST Rules](#Creating-SAST-Rules)

  - [Steps](#Steps)

  - [Example yml rule](#Example-yml-rule)

  - [Important to note](#Important-to-note)

  - [Create test for rule](#Create-test-for-rule)

  - [Example of test file code for rule](#Example-of-test-file-code-for-rule)

[Creating Reachability Rules for Aqua](#Creating-Reachability-Rules-for-Aqua)
  - [Please Note](#Please-Note)

  - [Steps](#Steps)
  
  - [Example of tpl file](#Example-of-tpl-file)

  - [Converted rule to tpl](#Converted-rule-to-tpl)

  - [Create a test rechability test file](#Create-a-test-rechability-test-file)

  - [Example test code for rechability](#Example-test-code-for-rechability)

## Setup

### Semgrep Installation: 
  1. For Mac:
     `brew install semgrep`
     Alternative
     `python3 -m pip install semgrep`
     
  2. For Ubuntu or Windows: 
      `python3 -m pip install semgrep`
      
  3. Check Version
     `semgrep --version`
     
### Steps for Project Setup:
  1. Clone the project: `git clone <repo name>`
  2. Command to run the Unit Test: `semgrep --test --config tests/rules/bash/ tests/targets/bash`

## Creating SAST Rules

### Steps
  1. Pick Language of choice. eg is javascript, navigate to **sast-rules->sast->aqua->js**.
  2. Create rule in **.yml** format.
  3. Create same rule in semgrep folder located at **sast-rules->sast->semgrep->js**.
  4. Create test case for the rule in **sast-rules->sast-tests->js**.
  5. Rule should be in yml format of the code, eg **.yml**.

### Example yml rule
```yaml
rules:
  - id: risky-react-markdown
    message: Overwriting transformLinkUri or transformImageUri, enabling allowDangerousHtml, or disabling escapeHtml functionality can expose the code to XSS vulnerabilities.
    metadata:
      cwe:
        - "CWE-79: Improper Neutralization of Input During Web Page Generation
          ('Cross-site Scripting')"
      owasp:
        - A03:2021 - Injection
      references:
        - https://owasp.org/Top10/A03_2021-Injection/
        - https://cwe.mitre.org/data/definitions/79.html
      category: security
      technology:
        - react
      cwe2022-top25: true
      cwe2021-top25: true
      subcategory:
        - audit
      likelihood: LOW
      impact: LOW
      confidence: LOW
      license: Commons Clause License Condition v1.0[LGPL-2.1-only]
      vulnerability_class:
        - Cross-Site-Scripting (XSS)
    languages:
      - typescript
      - javascript
    severity: WARNING
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern-inside: |
                  $X = require('$LIB');
                  ...
              - pattern-inside: |
                  import '$LIB';
                  ...
          - metavariable-regex:
              metavariable: $LIB
              regex: (react-markdown/with-html|react-markdown)
    pattern-sinks:
      - pattern: |
          <$EL allowDangerousHtml />
      - pattern: |
          <$EL escapeHtml={false} />
      - patterns:
          - pattern: |
              <$EL $VAR=... />
          - metavariable-regex:
              metavariable: $VAR
              regex: (transformLinkUri|transformImageUri)

```
### Important to note
  1. Rule ID should include text, numbers or '-' characters
  2. The order should be id, severerity, languages, metadata, message and pattern(s).
  3. Metadata tag should be include with sub categories like **CWE, OWASP, Category, technology, impact, confidence,     likelihood, references, vulnerability_class**.

### Create test for rule
  1. The name of the test should be same as name of rule.
  2. Tests must be created at **sast->tests->js**. In our example the rule was written in JS hence the file will be place in the js folder.
  3. Tests should include both negative test and positive tests.
  4. Negative test are test which doesn't match the rule/test. Format **// ok: risky-react-markdown**
  5. Positive tests are test that match the rule/test. Format **// ruleid: risky-react-markdown**.
  6. Tests should be in the file format of the language. In our example **.js**.


### Example of test file code for rule.
```javascript

import ReactMarkdown from "react-markdown";
import htmlParser from "react-markdown/plugins/html-parser";

// For more info on the processing instructions, see
// <https://github.com/aknuds1/html-to-react#with-custom-processing-instructions>
const parseHtml = htmlParser({
  isValidNode: (node) => node.type !== 'script',
  processingInstructions: [
    /* ... */
  ]
})

function bad1() {
// ruleid: risky-react-markdown
    return <ReactMarkdown astPlugins={[parseHtml]} allowDangerousHtml children={markdown} />;
}

function bad2() {
// ruleid: risky-react-markdown
    return <ReactMarkdown astPlugins={[parseHtml]} escapeHtml={false} children={markdown} />;
}

function ok1() {
// ok: risky-react-markdown
    return <ReactMarkdown renderers={renderers} children={markdown} />;
}

function ok2() {
// ok: risky-react-markdown
    return <ReactMarkdown renderers={renderers} escapeHtml={true} children={markdown} />;
}

```
### Open the rules-mapping.json file in the test folder of the language.

  1. Place the test at the bottom of the file 
     Eg: **"sast.semgrep.js.react-markdown-insecure-html": "sast.aqua.js.risky-react-markdown"**

## Creating Reachability Rules for Aqua
### Please Note
  **In reachability rules certain things must be taken into consideration**
  1. Vulberabile ID represented as {{ .VulnerabilityID }}. This denotes the CVE number.
  2. Name represented as {{ .Name }}. This denotes the vulnerable library.
  3. Type represented as {{ .Type }}. This denotes the package.

### Steps
  1. Pick language of your choice eg javascript.
  3. Navigate to **sast-rules->npm**.
  3. Create file in .tpl format.

### Example of tpl file

```tpl
rules:
  - id: is_reachable_{{ .Type }}_{{ .Name }}_{{ .VulnerabilityID }}
    message: reachable vulnrable pacakge
    metadata:
      package: "{{ .Name }}"
      vulnerabilityID: "{{ .VulnerabilityID }}"
      category: security
      subcategory:
        - vuln-reachable
    languages:
      - javascript
      - typescript
    severity: INFO
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-inside: |
              const {VM} = require("$LIB");
              ...
          - metavariable-regex:
              metavariable: $LIB
              regex: ({{ .Name }})
    pattern-sinks:
        - patterns:
          - pattern-either:
            - pattern: >
                code = Error.$PST = (...) =>
                {frames.$CONS.$CONS('...')().mainModule.$R('...').$ES('...');
                };(()=>{}).$CONS('...')()
            - pattern: >
                code = Error.$PST = (...) =>
                {frames.$CONS.$CONS('...')().mainModule.$R('...').$ES('...');
                };async function aa(){...(...)}
          - metavariable-regex:
                metavariable: $PST
                regex: (prepareStackTrace)

```

### Converted rule to tpl

```yaml

rules:
  - id: vm2-sandbox-escape-CVE-2023-29017
    message: Prior to version 3.9.15, vm2 was not properly handling host objects
      passed to `Error.prepareStackTrace` in case of unhandled async errors.
    metadata:
      owasp:
        - A03:2021 - Injection
      cwe:
        - "CWE-94: Improper Control of Generation of Code ('Code Injection')"
      category: security
      technology:
        - vm2
      cwe2022-top25: true
      subcategory:
        - audit
      likelihood: LOW
      impact: HIGH
      confidence: LOW
      references:
        - https://owasp.org/Top10/A03_2021-Injection
      license: Commons Clause License Condition v1.0[LGPL-2.1-only]
      vulnerability_class:
        - Code Injection
    languages:
      - javascript
      - typescript
    severity: WARNING
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-inside: |
              const {VM} = require("$LIB");
              ...
              $X = new VM();
          - pattern: |
              new VM();
          - metavariable-regex:
              metavariable: $LIB
              regex: (vm2)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: >
                  $CD = $ERROR.$STACK = (...) => {
                      $F.$CONST.$CONST(...)().mainModule.require(...).execSync(...); 
                  };(async ()=>{}).$CONST('return process')()

                  $PST.run($CD);
              - pattern: >
                  $CD = 
                   $ERROR.$STACK = (...) => {
                       frames.$CONST.$CONST(...)().mainModule.require(...).execSync(...); };async function aa(){
                       eval(...)} aa()
                       $PST.run($CD);
          - metavariable-regex:
              metavariable: $CONST
              regex: (constructor)
          - focus-metavariable: $PST
```
  1. {{ .Name }} = vm2.
  2. {{ .Type }} = npm.
  3. {{ .VulnerabilityID }} = CVE ID (2023-29017).

### Create a test rechability test file
  1. In our example the test will be created at **sast->reachability->npm**.
  2. File name should begin with rechable eg **rechable_vm2_CVE-2023-29017.js**.
  3. Test file should include both negative and positve tests.
  4. Add the vulnerable library to the package.json file.
  5. Run the run in cli **"npm i --package-lock"** to auto generate the package.lock.json.

### Example test code for rechability

```javascript
const {VM} = require("vm2");

let vmInstance = new VM();

const code = code;

// ruleid: is_reachable_npm_vm2_CVE-2023-29017
 code = Error.prepareStackTrace = (e, frames) => {
    frames.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch flag'); 
};
(async ()=>{}).constructor('return process')()


vmInstance.run(code);

// ruleid: is_reachable_npm_vm2_CVE-2023-29017
code = 
Error.prepareStackTrace = (e, frames) => {
    frames.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch flag'); 
};
async function aa(){
    eval("1=1")
}
aa()


vmInstance.run(code);

```


