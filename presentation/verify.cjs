/** Reject incomplete decks, missing notes and flattened evidence before delivery. */
const fs = require('node:fs/promises');
const assert = require('node:assert/strict');
const JSZip = require('jszip');

async function verify() {
  assert.ok(process.argv[2], 'Provide the path to the generated PPTX');
  const archive = await JSZip.loadAsync(await fs.readFile(process.argv[2]));
  const slides = Object.keys(archive.files).filter(name => /^ppt\/slides\/slide\d+\.xml$/.test(name));
  const notes = Object.keys(archive.files).filter(name => /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(name));
  assert.equal(slides.length, 20, 'The requested presentation must contain exactly twenty slides');
  assert.equal(notes.length, 20, 'Every slide must retain its speaker notes');
  for (let number = 1; number <= 20; number++) {
    const slide = await archive.file(`ppt/slides/slide${number}.xml`).async('string');
    const note = await archive.file(`ppt/notesSlides/notesSlide${number}.xml`).async('string');
    assert.match(note, /Tempo sugerido:/, `Slide ${number} needs timed speaker notes`);
    assert.match(note, /Fontes:/, `Slide ${number} needs traceable sources`);
    assert.doesNotMatch(slide, /lorem ipsum|\[preencher\]|\[insert|TODO/i,
      `Slide ${number} contains unresolved template content`);
    if ([5, 7, 11, 15, 17].includes(number)) {
      assert.match(slide, /<a:tbl>/, `Slide ${number} must retain an editable table`);
    }
  }
  const resultSlide = await archive.file('ppt/slides/slide16.xml').async('string');
  assert.match(resultSlide, /<c:chart /, 'Semantic evaluation must be a native chart');
  const chart = await archive.file('ppt/charts/chart1.xml').async('string');
  assert.match(chart, /<c:v>25<\/c:v>/, 'The chart must preserve 25 detected semantic errors');
  assert.match(chart, /<c:v>10<\/c:v>/, 'The chart must preserve 10 accepted controls');
  const tokenSlide = await archive.file('ppt/slides/slide5.xml').async('string');
  assert.match(tokenSlide, /<a:t>INT<\/a:t>/, 'The slide must use the lexer token name INT');
  process.stdout.write('Deck verified: 20 slides, 20 notes, 5 native tables and 1 native chart.\n');
}

verify().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
