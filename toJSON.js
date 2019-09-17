const fs = require('fs');

// Please update these according to your files!
const WORKSPACE_NAME = 'menetelmätieteet'
const INPUT_FILE = 'courses.md'
const OUTPUT_FILE = 'output.json'

/* 

Example snippet of markdown format:

## TKT10003 - Ohjelmoinnin jatkokurssi

- Perintä ja rajapinta
- Periytyvät luokat ja rajapinnan toteuttavat luokat
- Osaat luoda luokkia, jotka periytyvät toisesta luokasta ja osaat luoda luokkia, jotka toteuttavat yhden tai useamman rajapinnan
- Abstraktien luokkien toiminta
- Tiedät miten abstraktit luokat toimivat.  Ymmärrät että olio voidaan esittää kaikkien sen todellisten tyyppien avulla
- Tietokokoelmat virtana
- Osaat käsitellä tietokokoelmia virran avulla

Example snippet of json format:

{
  "workspace": "menetelmätieteet",
  "courses": [
  {
    "code": "MAT11001", 
    "name": "Johdatus yliopistomatematiikkaan",
    "tags": [],
    "official": false,
    "concepts": [
      {
        "name": "induktio",
        "description": "",
        "tags": [],
        "official": false,
        "prerequisites": []
      },
    ],
    "prerequisites": []
  },
*/

function newResultJson(workspace) {
  return {
    workspace: workspace,
    courses: []
  }
}

function newCourse(code, name) {
  return {
    code: code, 
    name: name,
    tags: [],
    official: false,
    concepts: [],
    prerequisites: []
  }
}

function newConcept(name) {
  return {
    name: name,
    description: "",
    tags: [],
    official: false,
    prerequisites: []
  }
}

function courseRowsToObj(rows) {
  const code = rows[0].split(" - ")[0]
  const name = rows[0].split(" - ")[1]
  const course = newCourse(code, name)
  const concepts = []
  rows.forEach(row => {
    if (row.startsWith("- ")) {
      concepts.push(newConcept(row.replace("- ", "")))
    } else if (row.startsWith("  - ")) {
      concepts[concepts.length - 1].description = row.replace("  - ", "")
    }
  })
  course.concepts = concepts
  return course
}

function toJSON(markdown) {
  return markdown
    .split("## ")
    .slice(1)
    .map(course => {
      return courseRowsToObj(course.split("\n"))
    })
}

const markdownInput = fs.readFileSync(INPUT_FILE, 'utf8')

const result = newResultJson(WORKSPACE_NAME)

result.courses = toJSON(markdownInput)

fs.writeFileSync(OUTPUT_FILE, JSON.stringify(result), 'utf8')
