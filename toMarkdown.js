const fs = require('fs');

const INPUT_FILE = 'courses.json'
const OUTPUT_FILE = 'courses.md'

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


function jsonToMarkdown(jsonObj) {
  resultLines = []
  
  resultLines.push('# Courses' + '\n')
  
  jsonObj.courses.forEach(course => {
    resultLines.push('## ' + (course.code ? course.code + ' - ' : '') + course.name + '')
    if (course.concepts.length > 0) {
      resultLines.push('') //empty row before concepts
    }
    course.concepts.forEach(concept => {
      resultLines.push('- ' + concept.name)
      if (concept.description) {
        resultLines.push('  - ' + concept.description.replace(/(\r\n|\n|\r)/gm," "))
      }
    })
    resultLines.push('')
  })
  fs.writeFileSync(OUTPUT_FILE, resultLines.join('\n'))
}

const obj = JSON.parse(fs.readFileSync(INPUT_FILE, 'utf8'));

jsonToMarkdown(obj)
