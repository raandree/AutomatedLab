---
applyTo: "**/*.yml,**/*.yaml"
---

# YAML Best Practices and Standards

When working with YAML files, adhere to the following comprehensive guidelines derived from the YAML 1.2 specification and community best practices.

## Core Principles

### What is YAML?
- **Y**AML **A**in't **M**arkup **L**anguage
- Human-readable data serialization format
- Superset of JSON (all JSON is valid YAML)
- Three basic data structures: mappings (hashes/dictionaries), sequences (arrays/lists), scalars (strings/numbers)

### Design Goals
- **Readable**: Easy for humans to read and write
- **Portable**: Works across programming languages
- **Expressive**: Supports complex data structures
- **Minimal**: Low syntax overhead

## Indentation Rules

### Use Spaces, Never Tabs
```yaml
# Correct - using 2 spaces
parent:
  child:
    grandchild: value

# Incorrect - using tabs
parent:
child:  # TAB characters will cause errors
grandchild: value
```

### Consistent Indentation Levels
- **Standard**: Use 2 spaces per indentation level (most common)
- **Alternative**: 4 spaces (less common, but acceptable if consistent)
- **NEVER mix**: Always use the same indentation width throughout a file

```yaml
# Good - consistent 2-space indentation
root:
  level1:
    level2:
      level3: value

# Bad - mixed indentation
root:
  level1:
      level2:  # 4 spaces instead of 2
    level3: value  # Back to 2 spaces
```

### Indentation for Lists
```yaml
# Correct - list items at same level as parent
items:
  - first
  - second
  - third

# Also correct - inline
items: [first, second, third]

# Nested lists
outer:
  - item1
  - item2
  - nested:
      - subitem1
      - subitem2
```

## Mappings (Key-Value Pairs)

### Basic Syntax
```yaml
# Simple key-value
key: value
name: John Doe
age: 30

# Nested mappings
person:
  name: John Doe
  age: 30
  address:
    street: 123 Main St
    city: Springfield
```

### Key Naming Conventions
```yaml
# Preferred - lowercase with underscores (snake_case)
database_connection: localhost
max_retry_count: 3

# Also acceptable - camelCase
databaseConnection: localhost
maxRetryCount: 3

# Acceptable - kebab-case
database-connection: localhost
max-retry-count: 3

# Less readable - PascalCase (avoid unless required)
DatabaseConnection: localhost
MaxRetryCount: 3
```

### Explicit Keys (Complex Keys)
```yaml
# When keys contain special characters
? "key with spaces"
: value

? [complex, key]
: value

# Better: avoid complex keys when possible
key_with_underscores: value
```

## Sequences (Lists/Arrays)

### Block Style (Preferred for Readability)
```yaml
# Simple list
fruits:
  - apple
  - banana
  - orange

# List of mappings
users:
  - name: Alice
    role: admin
  - name: Bob
    role: user
```

### Flow Style (Compact)
```yaml
# Inline list
fruits: [apple, banana, orange]

# Inline mapping
user: {name: Alice, role: admin}

# Mixed
users: [{name: Alice, role: admin}, {name: Bob, role: user}]
```

### When to Use Each Style
- **Block style**: Use for multi-item lists, better readability
- **Flow style**: Use for short lists (1-3 items), or when space is limited

## Scalars (Strings, Numbers, Booleans)

### Strings

#### Unquoted Strings
```yaml
# Simple strings don't need quotes
name: John Doe
message: Hello World

# Be careful with special characters
# These need quotes:
special: "value: with colon"
numbers: "123"  # If you want it as string, not number
```

#### Quoted Strings
```yaml
# Single quotes - literal (no escape sequences)
message: 'This is a string'
escaped: 'Use '' for a single quote'

# Double quotes - allow escape sequences
message: "Line 1\nLine 2"  # \n creates newline
path: "C:\\Users\\Name"    # \\ for backslash
unicode: "Unicode: \u0041"  # \u for unicode
```

#### Multi-line Strings

##### Literal Block Scalar (Preserve newlines)
```yaml
# Pipe | preserves newlines
script: |
  #!/bin/bash
  echo "Line 1"
  echo "Line 2"
  echo "Line 3"

# Result: "#!/bin/bash\necho \"Line 1\"\necho \"Line 2\"\necho \"Line 3\"\n"
```

##### Folded Block Scalar (Join lines)
```yaml
# Greater-than > folds newlines into spaces
description: >
  This is a long description
  that spans multiple lines
  but will be joined into
  a single line.

# Result: "This is a long description that spans multiple lines but will be joined into a single line.\n"
```

##### Block Chomping
```yaml
# Default - keep final newline
text: |
  content

# Strip final newlines: |-
text: |-
  content

# Keep all final newlines: |+
text: |+
  content


```

#### When to Quote Strings
```yaml
# Must quote
colon_value: "value: with colon"
hash_value: "value # with hash"
at_value: "@value starting with @"
backtick_value: "`value with backticks"
boolean_string: "true"  # To prevent interpretation as boolean
number_string: "123"    # To prevent interpretation as number

# No need to quote
simple: value
with_spaces: this is fine
with-dashes: also-fine
with_underscores: also_fine
```

### Numbers
```yaml
# Integers
integer: 42
negative: -17
octal: 0o14        # Octal notation
hexadecimal: 0x1A  # Hex notation

# Floats
float: 3.14159
scientific: 1.23e+3
infinity: .inf
not_a_number: .nan

# As strings (quoted)
version: "1.0"
port: "8080"
```

### Booleans
```yaml
# True values
enabled: true
enabled: True
enabled: TRUE
enabled: yes
enabled: Yes
enabled: on

# False values
disabled: false
disabled: False
disabled: FALSE
disabled: no
disabled: No
disabled: off

# Recommended: use lowercase true/false for clarity
recommended_true: true
recommended_false: false
```

### Null Values
```yaml
# Explicit null
value: null
value: Null
value: NULL
value: ~

# Empty value (also null)
value:

# Recommended: use null for clarity
recommended:
```

## Comments

### Single-line Comments
```yaml
# This is a comment
key: value  # Inline comment

# Multi-line comment block
# Line 1 of comment
# Line 2 of comment
key: value
```

### Comment Best Practices
```yaml
# Good - explain WHY, not WHAT
# Retry count increased due to network instability in production
max_retries: 5

# Bad - states the obvious
# This sets the max retries
max_retries: 5

# Section headers
# ============================================================
# Database Configuration
# ============================================================
database:
  host: localhost
  port: 5432
```

## Anchors and Aliases (DRY Principle)

### Basic Anchors and Aliases
```yaml
# Define anchor with &
defaults: &default_settings
  timeout: 30
  retries: 3

# Reference with *
development:
  <<: *default_settings
  host: dev.example.com

production:
  <<: *default_settings
  host: prod.example.com
  timeout: 60  # Override specific value
```

### Merge Keys
```yaml
# Base configuration
base: &base
  name: Base
  version: 1.0

# Merge and extend
extended:
  <<: *base
  description: Extended configuration
  version: 2.0  # Overrides base version

# Result of extended:
# name: Base
# version: 2.0
# description: Extended configuration
```

### Multiple Merges
```yaml
default_timeouts: &timeouts
  connect_timeout: 5
  read_timeout: 30

default_retries: &retries
  max_retries: 3
  retry_delay: 1

service:
  <<: [*timeouts, *retries]
  host: example.com
```

## Document Structure

### Single Document
```yaml
# Simple document
key: value
another: value
```

### Multiple Documents in One File
```yaml
---
# Document 1
name: First Document
value: 123
---
# Document 2
name: Second Document
value: 456
...
```

### Document Markers
```yaml
# --- marks document start (optional for single document)
---
content: here

# ... marks document end (optional)
...
```

## Common YAML Structures

### Configuration Files
```yaml
---
application:
  name: MyApp
  version: 1.0.0
  
database:
  host: localhost
  port: 5432
  credentials:
    username: admin
    password: secure_password
    
logging:
  level: info
  outputs:
    - console
    - file
  file:
    path: /var/log/app.log
    max_size: 10MB
```

### CI/CD Pipeline (Azure Pipelines / GitHub Actions)
```yaml
---
name: Build Pipeline

trigger:
  branches:
    include:
      - main
      - develop

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: PowerShell@2
            displayName: 'Run Tests'
            inputs:
              targetType: 'inline'
              script: |
                Invoke-Pester -Output Detailed
```

### Docker Compose
```yaml
---
version: '3.8'

services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./html:/usr/share/nginx/html
    environment:
      - NGINX_HOST=localhost
      - NGINX_PORT=80
    depends_on:
      - db
      
  db:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: example
    volumes:
      - db-data:/var/lib/postgresql/data

volumes:
  db-data:
```

## Type Safety and Explicit Typing

### Explicit Type Tags
```yaml
# String (when ambiguous)
version: !!str 1.0
port: !!str 8080

# Integer
count: !!int 42

# Float
price: !!float 19.99

# Boolean
enabled: !!bool true

# Null
value: !!null

# Binary
picture: !!binary |
  R0lGODlhDAAMAIQAAP//9/X17unp5WZmZgAAAOfn515eXvPz7Y6OjuDg4J+fn5
```

### When to Use Explicit Types
- When the intended type might be ambiguous
- When interfacing with strongly-typed systems
- When you need to ensure a specific interpretation

## Best Practices Summary

### DO
- ✅ Use 2-space indentation consistently
- ✅ Use lowercase `true`/`false` for booleans
- ✅ Quote strings that contain special characters
- ✅ Use block style for lists (better readability)
- ✅ Add comments to explain WHY, not WHAT
- ✅ Use anchors and aliases to avoid repetition
- ✅ Keep lines under 100 characters when possible
- ✅ Use meaningful key names
- ✅ Validate YAML with a linter
- ✅ Use `---` at document start for multi-document files

### DON'T
- ❌ Never use tabs for indentation
- ❌ Don't mix indentation widths
- ❌ Don't over-use flow style (less readable)
- ❌ Don't use complex keys unless necessary
- ❌ Don't leave trailing whitespace
- ❌ Don't trust unquoted strings with special characters
- ❌ Don't use deprecated YAML 1.0/1.1 syntax
- ❌ Don't repeat configuration (use anchors instead)

## Common Pitfalls

### Pitfall 1: Unquoted Special Characters
```yaml
# Wrong - will cause parse error
message: Value: with colon

# Right
message: "Value: with colon"
```

### Pitfall 2: Indentation Errors
```yaml
# Wrong - inconsistent indentation
parent:
  child1: value
    child2: value  # Too much indentation

# Right
parent:
  child1: value
  child2: value
```

### Pitfall 3: Tab Characters
```yaml
# Wrong - contains tabs (invisible here but causes errors)
key:value

# Right - uses spaces
key: value
```

### Pitfall 4: Boolean/Number Confusion
```yaml
# Interpreted as boolean true
norway: no  # !!!

# Interpreted as string "no"
norway: "no"

# Interpreted as number
version: 1.0

# Interpreted as string "1.0"
version: "1.0"
```

### Pitfall 5: Trailing Colons
```yaml
# Wrong - missing space after colon
key:value

# Right
key: value
```

## Validation and Linting

### Validate YAML Syntax
```yaml
# Use online validators:
# - https://www.yamllint.com/
# - https://yamlchecker.com/

# Or command-line tools:
# yamllint file.yaml
# python -c "import yaml; yaml.safe_load(open('file.yaml'))"
```

### YAMLLint Configuration
```yaml
# .yamllint
---
extends: default

rules:
  line-length:
    max: 120
    level: warning
  indentation:
    spaces: 2
    indent-sequences: true
  comments:
    min-spaces-from-content: 2
```

## Tool-Specific Conventions

### PowerShell (build.yaml for Sampler)
```yaml
---
BuildWorkflow:
  '.':
    - build
    - test

  build:
    - Clean
    - Build_Module_ModuleBuilder
    - Build_NestedModules_ModuleBuilder
    - Create_changelog_release_output

  test:
    - Pester_Tests_Stop_On_Fail
    - Pester_if_Code_Coverage_Under_Threshold

ModuleBuildTasks:
  Sampler:
    - '*.build.Sampler.ib.tasks'
```

### Azure Pipelines
```yaml
---
trigger:
  - main

pool:
  vmImage: 'windows-latest'

variables:
  buildConfiguration: 'Release'

steps:
  - task: PowerShell@2
    inputs:
      targetType: 'inline'
      script: Write-Host "Building..."
```

## Summary Checklist

- ✅ Spaces only, never tabs
- ✅ Consistent 2-space indentation
- ✅ Quote strings with special characters
- ✅ Use lowercase true/false
- ✅ Comment why, not what
- ✅ Use anchors to avoid repetition
- ✅ Validate with yamllint
- ✅ Keep lines reasonable length
- ✅ Use block style for readability
- ✅ Be explicit when ambiguous (use quotes or tags)
