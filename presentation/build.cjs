/** Build the editable twenty-slide academic presentation without changing the compiler. */
const fs = require('node:fs/promises');
const path = require('node:path');
const pptxgen = require('pptxgenjs');
const { renderIcons } = require('./render-icons.cjs');

const ROOT = path.resolve(__dirname, '..');
const C = Object.freeze({
  bg: '0B1324', cyan: '10BCD8', purple: '7B6FF0', white: 'F8FAFC',
  muted: 'CBD5E1', quiet: '8796AD', card: '1E293B', panel: '0F1C30',
  code: '060A19', border: '283449', green: '4ADE80', red: 'FF4E58',
  circleBlue: '122B3F', circlePurple: '1D1D40',
});
const W = 13.333333;
const H = 7.5;
// Public abbreviated Git revision of the academic implementation, not a credential.
const COMMIT = '5a56802';
const REPO = 'https://github.com/Mathwesm/NetSec';
const SOURCE = `${REPO}/blob/${COMMIT}/`;
const notes = [];
const seconds = [15, 30, 45, 30, 30, 35, 30, 40, 40, 30, 25, 30, 30, 105, 35, 35, 25, 25, 30, 10];

function text(slide, value, x, y, w, h, options = {}) {
  slide.addText(value, {
    x, y, w, h, isTextBox: true, margin: 0, fontFace: 'Calibri',
    fontSize: 19, color: C.muted, breakLine: false, valign: 'mid',
    ...options,
  });
}

function panel(slide, x, y, w, h, fill = C.card) {
  slide.addShape('roundRect', {
    x, y, w, h, radius: 0.12, rectRadius: 0.12,
    fill: { color: fill }, line: { color: C.border, width: 0.6 },
  });
}

function circleIcon(slide, icons, name, x, y, size = 0.65, color = C.cyan) {
  slide.addShape('ellipse', { x, y, w: size, h: size,
    fill: { color }, line: { color, transparency: 100 } });
  slide.addImage({ data: icons[`${name}_dark`], x: x + size * 0.23,
    y: y + size * 0.23, w: size * 0.54, h: size * 0.54 });
}

function base(pres, icons, title, accent, icon, subtitle = '') {
  const slide = pres.addSlide();
  slide.background = { color: C.bg };
  // Reproduce the two clipped circles used throughout the supplied PDF.
  slide.addShape('ellipse', { x: -1.12, y: -1.1, w: 3.78, h: 3.68,
    fill: { color: C.circleBlue }, line: { transparency: 100 } });
  slide.addShape('ellipse', { x: 9.5, y: 5.15, w: 5.1, h: 3.62,
    fill: { color: C.circlePurple }, line: { transparency: 100 } });
  if (title) {
    text(slide, [{ text: title, options: { color: C.white } },
      { text: accent, options: { color: C.cyan } }], 0.65, 0.32, 11.45, 0.58,
    { fontFace: 'Arial', fontSize: 29, bold: true, align: 'center' });
    circleIcon(slide, icons, icon, 12.02, 0.34, 0.68, C.purple);
  }
  if (subtitle) text(slide, subtitle, 0.75, 1.08, 11.8, 0.42,
    { fontSize: 18, align: 'center' });
  text(slide, 'NetSec  ·  Redes + Segurança + Automação', 0.55, 7.17, 8.5, 0.18,
    { fontSize: 8.5, color: C.quiet });
  text(slide, String(pres._slides.length), 12.35, 7.16, 0.35, 0.2,
    { fontSize: 8.5, color: C.quiet, align: 'right' });
  return slide;
}

function note(slide, title, speech, files = [], extra = []) {
  const number = notes.length + 1;
  const sources = files.map(file => file === 'docs/evolucao.md'
    ? `${REPO}/blob/feat/academic-presentation/${file}` : SOURCE + file).concat(extra);
  const body = `Tempo sugerido: ${seconds[number - 1]} segundos.\n\n${speech}\n\nFontes:\n${sources.join('\n')}`;
  slide.addNotes(body);
  notes.push({ number, title, seconds: seconds[number - 1], body });
}

function syntax(line) {
  return line.split(/("(?:[^"\\]|\\.)*"|\/\/.*|\b(?:group|host|address|play|targets|check|service|firewall|allow|deny|report|port|protocol|network|int|bool|if|else|repeat|in|and|return|def)\b|\b\d+\b)/g)
    .filter(Boolean).map(token => ({ text: token, options: {
      color: token.startsWith('//') ? C.quiet : token.startsWith('"') ? C.green
        : /^(deny|E_[A-Z_]+)$/.test(token) ? C.red
          : /^(\d+|tcp|udp)$/.test(token) ? C.cyan
            : /^(group|host|address|play|targets|check|service|firewall|allow|report|port|protocol|network|int|bool|if|else|repeat|in|and|return|def)$/.test(token)
              ? C.purple : C.white,
    } }));
}

function code(slide, source, x, y, w, h, fontSize = 16) {
  panel(slide, x, y, w, h, C.code);
  const lines = source.trimEnd().split('\n');
  const step = (h - 0.38) / lines.length;
  lines.forEach((line, index) => text(slide, syntax(line), x + 0.24,
    y + 0.18 + index * step, w - 0.48, step,
    { fontFace: 'Courier New', fontSize, valign: 'mid', breakLine: false }));
}

function point(slide, icons, icon, heading, body, x, y, w, color = C.cyan) {
  circleIcon(slide, icons, icon, x, y, 0.58, color);
  text(slide, heading, x + 0.8, y - 0.02, w - 0.8, 0.42,
    { fontSize: 21, bold: true, color: C.white });
  text(slide, body, x + 0.8, y + 0.47, w - 0.8, 0.83,
    { fontSize: 18, valign: 'top' });
}

function arrow(slide, x1, y1, x2, y2, color = C.purple) {
  slide.addShape('line', { x: x1, y: y1, w: x2 - x1, h: y2 - y1,
    line: { color, width: 2.2, beginArrowType: 'none', endArrowType: 'triangle' } });
}

function table(slide, headers, rows, x, y, w, widths, rowHeight = 0.68, fontSize = 18) {
  const data = [headers.map(value => ({ text: value, options: {
    bold: true, color: C.cyan, fill: C.panel,
  } })), ...rows.map((row, index) => row.map(value => ({ text: value, options: {
    fill: index % 2 === 0 ? C.card : C.panel,
  } })))];
  slide.addTable(data, { x, y, w, colW: widths, rowH: rowHeight, margin: 0.13,
    border: { type: 'solid', color: C.border, pt: 0.7 },
    color: C.white, fontFace: 'Calibri', fontSize, valign: 'mid',
    autoPage: false, verbose: false, breakLine: false,
  });
}

async function build() {
  const output = path.resolve(process.argv[2] || path.join(ROOT, 'data', 'presentation-build', new Date().toISOString().replaceAll(':', '-')));
  // Exclusive creation prevents accidental replacement of a previous result.
  await fs.mkdir(path.dirname(output), { recursive: true });
  await fs.mkdir(output);
  const icons = await renderIcons();
  const pres = new pptxgen();
  pres.layout = 'LAYOUT_WIDE';
  pres.author = 'Matheus';
  pres.subject = 'Implementação e demonstração da linguagem NetSec';
  pres.title = 'NetSec: linguagem para redes e segurança';
  pres.company = 'NetSec';
  pres.lang = 'pt-BR';
  pres.theme = { headFontFace: 'Arial', bodyFontFace: 'Calibri', lang: 'pt-BR' };

  cover(pres, icons);
  purpose(pres, icons);
  program(pres, icons);
  architecture(pres, icons);
  grammar(pres, icons);
  precedence(pres, icons);
  types(pres, icons);
  scopes(pres, icons);
  conflicts(pres, icons);
  runtime(pres, icons);
  adapters(pres, icons);
  editor(pres, icons);
  laboratory(pres, icons);
  demonstration(pres, icons);
  networkResults(pres, icons);
  semanticResults(pres, icons);
  quality(pres, icons);
  limitations(pres, icons);
  conclusion(pres, icons);
  references(pres, icons);

  if (pres._slides.length !== 20 || notes.length !== 20) throw new Error('Expected exactly twenty slides with notes');
  await pres.writeFile({ fileName: path.join(output, 'NetSec_Apresentacao_Academica.pptx') });
  await fs.writeFile(path.join(output, 'Roteiro_de_fala.md'),
    `# NetSec: roteiro de fala\n\nDuração planejada: ${seconds.reduce((a, b) => a + b, 0)} segundos.\n\n` +
    notes.map(item => `## ${item.number}. ${item.title}\n\n${item.body}\n`).join('\n'),
    { encoding: 'utf8', flag: 'wx' });
  await fs.writeFile(path.join(output, 'deck-manifest.json'), JSON.stringify({
    slides: notes.map(({ number, title, seconds: duration }) => ({ number, title, duration })),
    baseline: COMMIT, palette: C, width: W, height: H,
  }, null, 2), { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`Created ${output}\n`);
}

function cover(pres, icons) {
  const s = base(pres, icons, '', '', 'shield');
  circleIcon(s, icons, 'shield', 6.3, 0.85, 0.72);
  text(s, 'NetSec', 1, 1.9, 11.33, 0.85,
    { fontFace: 'Arial', fontSize: 46, bold: true, color: C.white, align: 'center' });
  text(s, 'Linguagem de programação para redes e segurança', 1.1, 3.04, 11.1, 0.5,
    { fontSize: 25, color: C.cyan, align: 'center' });
  text(s, 'Compilador próprio, tipos explícitos e uma demonstração de firewall real',
    1.3, 4.1, 10.7, 0.55, { fontSize: 20, italic: true, align: 'center' });
  [['network', 'Redes'], ['code', 'Linguagem'], ['shield', 'Segurança']].forEach(([icon, label], i) => {
    circleIcon(s, icons, icon, 3.12 + 2.5 * i, 5.28, 0.45, C.purple);
    text(s, label, 3.72 + 2.5 * i, 5.31, 1.6, 0.35, { fontSize: 17, color: C.quiet });
  });
  text(s, 'Projeto acadêmico de implementação de linguagem', 2, 6.28, 9.33, 0.4,
    { fontSize: 15, color: C.quiet, align: 'center' });
  note(s, 'NetSec', 'Apresente a NetSec como uma linguagem específica de domínio. O objetivo desta demonstração é explicar como o código escrito pelo usuário passa por um compilador próprio e chega a uma ação observável. O escopo validado de firewall é o laboratório Linux, não uma implantação de produção.', ['README.md', 'docs/especificacao.md']);
}

function purpose(pres, icons) {
  const s = base(pres, icons, 'Problema e ', 'objetivo', 'target',
    'Descrever políticas de rede com regras verificáveis antes da execução');
  panel(s, 0.75, 1.85, 5.7, 4.88);
  panel(s, 6.75, 1.85, 5.82, 4.88, C.panel);
  point(s, icons, 'warning', 'O problema', 'Comandos dispersos podem aplicar políticas contraditórias ao mesmo IP.', 1.08, 2.2, 4.9, C.purple);
  point(s, icons, 'network', 'Público e domínio', 'Estudantes e profissionais de redes, segurança e infraestrutura.', 1.08, 4.25, 4.9);
  text(s, 'Objetivo da linguagem', 7.1, 2.25, 4.8, 0.5, { color: C.cyan, bold: true, fontSize: 25 });
  text(s, 'Declarar hosts e políticas com tipos explícitos.\n\nRejeitar inconsistências com localização no código.\n\nExecutar checks e regras em um ambiente definido.', 7.1, 3.06, 4.85, 2.76, { fontSize: 22, valign: 'top' });
  text(s, 'Roteiro: código, compilação, execução e evidências', 1.1, 6.1, 5.0, 0.45, { fontSize: 17, color: C.quiet });
  note(s, 'Problema e objetivo', 'Use um exemplo concreto: dois grupos podem apontar para o mesmo servidor, enquanto um play permite a porta 22 e outro a bloqueia. O diferencial acadêmico é detectar essa contradição antes de tocar na rede. Situe o público sem prometer provisionamento, roteamento ou monitoramento contínuo já implementados.', ['docs/especificacao.md']);
}

function program(pres, icons) {
  const s = base(pres, icons, 'Um programa ', 'completo', 'code',
    'O vocabulário representa inventário, verificações e política de firewall');
  code(s, 'port admin = port(22);\ngroup servers {\n  host "server01" address "192.0.2.10";\n}\nplay "protect" targets servers {\n  firewall deny port 23 protocol tcp;\n  firewall allow port admin protocol tcp;\n  check service "ssh";\n  report "Policy execution completed.";\n}', 0.75, 1.82, 8.1, 4.86, 17.5);
  point(s, icons, 'type', 'Tipo de domínio', 'port limita valores a 1..65535.', 9.12, 2.02, 3.5);
  point(s, icons, 'server', 'Alvo explícito', 'O grupo resolve cada host pelo IP.', 9.12, 3.58, 3.5, C.purple);
  point(s, icons, 'play', 'Execução por host', 'O play gera instruções ordenadas.', 9.12, 5.12, 3.5);
  note(s, 'Um programa completo', 'Leia o programa de cima para baixo. admin tem tipo port, e o construtor port(22) valida o domínio. O IP pertence ao bloco reservado para documentação, portanto este exemplo deve rodar em simulação. Explique que report é uma mensagem escrita pelo autor, não uma prova automática de sucesso. A prova está nos registros de execução. O código completo equivalente está nos exemplos do repositório.', ['examples/02_policy.netsec', 'docs/especificacao.md']);
}

function architecture(pres, icons) {
  const s = base(pres, icons, 'Arquitetura do ', 'compilador', 'route',
    'A análise do programa inteiro termina antes de qualquer efeito de rede');
  const stages = [
    ['tokens', 'Lexer', 'Texto em tokens', 'lexer.py'],
    ['tree', 'Parser', 'Tokens em AST', 'parser.py'],
    ['type', 'Semântica', 'Tipos e conflitos', 'values / compiler'],
    ['code', 'Plano', 'Instruções próprias', 'compiler.py'],
    ['play', 'Executor', 'Ações e registros', 'runtime.py'],
  ];
  stages.forEach(([icon, name, body, file], i) => {
    const x = 0.75 + i * 2.43;
    panel(s, x, 2.3, 2.13, 2.82, i === 2 ? '293257' : C.card);
    circleIcon(s, icons, icon, x + 0.73, 2.62, 0.65, i % 2 ? C.purple : C.cyan);
    text(s, name, x + 0.12, 3.5, 1.89, 0.45, { align: 'center', fontSize: 23, bold: true, color: C.white });
    text(s, body, x + 0.1, 4.03, 1.93, 0.48, { align: 'center', fontSize: 16 });
    text(s, file, x + 0.08, 4.6, 1.97, 0.25, { align: 'center', fontSize: 13, color: C.quiet });
    if (i < 4) arrow(s, x + 2.14, 3.69, x + 2.41, 3.69);
  });
  text(s, 'Front-end próprio', 0.9, 5.54, 7, 0.48, { color: C.cyan, bold: true, fontSize: 24 });
  text(s, 'Lexer manual, parser descendente recursivo e análise semântica implementada no projeto.', 0.9, 6.08, 11.5, 0.45, { fontSize: 20 });
  note(s, 'Arquitetura do compilador', 'Explique a separação entre sintaxe, significado e execução. A AST ainda pode representar um programa semanticamente inválido. A verificação de tipos e a expansão de grupos, condições e repetições produzem um plano próprio. Não usamos um analisador semântico pronto nem eval ou exec para executar NetSec. Pydantic cuida das fronteiras de dados, não das regras de tipos da linguagem.', ['src/netsec/core/lexer.py', 'src/netsec/core/parser.py', 'src/netsec/core/compiler.py', 'src/netsec/runtime.py']);
}

function grammar(pres, icons) {
  const s = base(pres, icons, 'Tokens e ', 'gramática', 'tokens',
    'Cada token conserva arquivo, linha e coluna');
  code(s, 'port admin = port(22);', 0.75, 1.77, 11.85, 0.77, 22);
  table(s, ['Lexema', 'Categoria', 'Posição inicial'], [
    ['port', 'palavra reservada / tipo', 'linha 1, coluna 1'],
    ['admin', 'NAME', 'linha 1, coluna 6'],
    ['22', 'INT', 'linha 1, coluna 19'],
  ], 0.75, 2.82, 11.85, [2.0, 6.0, 3.85], 0.56, 18);
  code(s, 'declaration = type, IDENTIFIER, "=", expression, ";" ;\nplay = "play", STRING, "targets", IDENTIFIER, block ;\nblock = "{", { statement }, "}" ;', 0.75, 5.35, 11.85, 1.2, 16.5);
  note(s, 'Tokens e gramática', 'Aponte que espaços e comentários não viram comandos, mas as posições são preservadas. A regra EBNF define a estrutura de declaração e a relação entre play, grupo e bloco. O exemplo usa os nomes da especificação; a implementação chama o token de identificador NAME. Um erro de ponto e vírgula é sintático. Um inteiro fora do intervalo de port é semântico.', ['src/netsec/core/lexer.py', 'src/netsec/core/parser.py', 'docs/especificacao.md']);
}

function precedence(pres, icons) {
  const s = base(pres, icons, 'AST e ', 'precedência', 'tree',
    'A árvore representa a ordem das operações antes da avaliação');
  code(s, 'int passes = 1 + 2 * 1;', 0.75, 1.75, 11.85, 0.78, 22);
  const node = (label, x, y, fill = C.card) => {
    panel(s, x, y, 1.1, 0.68, fill);
    text(s, label, x, y + 0.08, 1.1, 0.5, { align: 'center', fontSize: 26, bold: true, color: C.white });
  };
  arrow(s, 3.9, 3.75, 2.8, 4.6); arrow(s, 4.7, 3.75, 5.8, 4.6);
  arrow(s, 5.9, 5.2, 5.0, 5.95); arrow(s, 6.4, 5.2, 7.05, 5.95);
  node('+', 3.7, 3.1, '293257'); node('1', 2.0, 4.45); node('*', 5.5, 4.45, '293257');
  node('2', 4.35, 5.86); node('1', 6.72, 5.86);
  text(s, '* tem precedência sobre +', 8.5, 3.26, 3.5, 0.85, { fontSize: 25, color: C.cyan, bold: true });
  text(s, '1 + (2 * 1) = 3', 8.5, 4.55, 3.7, 0.6, { fontFace: 'Courier New', fontSize: 23, color: C.white });
  text(s, 'netsec ast mostra a estrutura\nnetsec compile resolve o valor', 8.5, 5.53, 3.65, 0.8, { fontSize: 18 });
  note(s, 'AST e precedência', 'Explique a árvore com o operador mais externo na raiz. O parser usa uma tabela de precedência: multiplicação tem nível 6, adição nível 5. Há também operadores lógicos, comparações e o operador de pertinência in. A avaliação resolve 3 durante a compilação. O diagrama é uma projeção da expressão, não a serialização completa de todos os campos da AST.', ['src/netsec/core/parser.py', 'src/netsec/core/values.py', 'examples/03_scopes.netsec']);
}

function types(pres, icons) {
  const s = base(pres, icons, 'Tipos e validação de ', 'domínio', 'type',
    'As declarações sempre informam o tipo. Não há inferência de declarações.');
  table(s, ['Tipo', 'Exemplo', 'Regra relevante'], [
    ['int, bool, string', 'int passes = 3;', 'bool não é int'],
    ['ip', 'ip node = ip("::1");', 'IPv4 / IPv6 válido e canônico'],
    ['network', 'network lan = network("192.0.2.0/24");', 'CIDR sem bits de host'],
    ['port', 'port admin = port(22);', 'Intervalo 1..65535'],
    ['protocol', 'protocol transport = tcp;', 'tcp ou udp'],
  ], 0.75, 1.9, 11.85, [2.05, 6.0, 3.8], 0.66, 17.5);
  text(s, 'Rejeitado: port admin = 22;', 1.1, 6.2, 5.7, 0.5,
    { color: C.red, fontFace: 'Courier New', fontSize: 21, bold: true });
  text(s, 'O construtor explícito é obrigatório nessa declaração.', 7.0, 6.1, 5.15, 0.8, { fontSize: 18 });
  note(s, 'Tipos e validação de domínio', 'Mostre que tipos de domínio são diferentes de um inteiro ou string genéricos. O construtor port valida os limites. O contexto check port 22 admite o literal por uma regra contextual documentada, mas port admin = 22 é rejeitado. As regras próprias de tipos estão em values.py. A biblioteca ipaddress valida somente os formatos de endereços e redes.', ['src/netsec/core/values.py', 'docs/especificacao.md'], ['https://docs.python.org/3.12/library/ipaddress.html']);
}

function scopes(pres, icons) {
  const s = base(pres, icons, 'Escopos e fluxo ', 'estático', 'scope',
    'Variáveis imutáveis, sombreamento local e repetição limitada');
  code(s, 'int passes = 3;\n// Inside a play:\nif current_host in trusted {\n  int passes = 2;\n  repeat passes {\n    check service "http";\n  }\n}\nreport passes;', 0.75, 1.85, 7.65, 4.83, 19);
  point(s, icons, 'scope', 'Escopo interno', 'passes vale 2 somente dentro do if.', 8.72, 2.02, 3.85);
  point(s, icons, 'play', 'Expansão', 'O compilador emite dois checks HTTP.', 8.72, 3.63, 3.85, C.purple);
  point(s, icons, 'code', 'Após o bloco', 'report passes produz 3.', 8.72, 5.24, 3.85);
  note(s, 'Escopos e fluxo estático', 'Este slide contém um trecho, não um programa completo. trusted é a rede declarada no exemplo 03, e current_host é o IP predefinido no play. Um bloco interno pode sombrear passes sem mudar a variável externa. Ambos os ramos de if são tipados, mas apenas o selecionado integra o plano. A condição não lê o resultado de um check. A repetição aceita de zero a cem iterações.', ['examples/03_scopes.netsec', 'src/netsec/core/compiler.py', 'src/netsec/core/values.py']);
}

function conflicts(pres, icons) {
  const s = base(pres, icons, 'Erro semântico: conflito por ', 'IP', 'warning',
    'Grupos diferentes não tornam válidas duas políticas opostas');
  [['first', 'allow', C.green], ['alias', 'deny', C.red]].forEach(([group, action, color], i) => {
    const x = 0.75 + i * 6.13;
    panel(s, x, 1.85, 5.73, 3.05);
    text(s, `Grupo ${group}`, x + 0.3, 2.13, 5.13, 0.45,
      { fontSize: 24, bold: true, color: C.white });
    text(s, '192.0.2.10', x + 0.3, 2.78, 5.13, 0.45, { fontFace: 'Courier New', fontSize: 25, color: C.cyan });
    code(s, `firewall ${action} port 22\n  protocol tcp;`, x + 0.28, 3.55, 5.17, 0.95, 18);
    text(s, action === 'allow' ? 'Permitir' : 'Bloquear', x + 3.7, 2.1, 1.7, 0.4,
      { color, fontSize: 19, bold: true, align: 'right' });
  });
  text(s, 'Chave semântica: (192.0.2.10, 22, tcp)', 1.0, 5.2, 11.35, 0.55,
    { fontFace: 'Courier New', fontSize: 22, align: 'center', color: C.white });
  code(s, '04_rejected.netsec:12:5\nE_FIREWALL_CONFLICT: Contradictory policies', 0.95, 5.95, 11.45, 0.8, 18);
  note(s, 'Erro semântico: conflito por IP', 'Execute o exemplo 04. O parser aceita a sintaxe. A análise semântica normaliza os IPs e compara a tripla IP, porta, protocolo ao longo do plano inteiro. A segunda política contradiz a primeira e gera E_FIREWALL_CONFLICT na linha 12, coluna 5. O objeto de diagnóstico também conserva a posição relacionada da regra anterior. O programa termina antes de iniciar qualquer ação. As instruções exibidas são recortes dos dois plays do exemplo.', ['examples/04_rejected.netsec', 'src/netsec/core/compiler.py', 'src/netsec/core/model.py']);
}

function runtime(pres, icons) {
  const s = base(pres, icons, 'Plano e executor ', 'próprios', 'play',
    'A NetSec gera instruções estruturadas e seleciona o adaptador em runtime');
  code(s, '{\n  "operation": "deny",\n  "host": "192.0.2.10",\n  "port": 23,\n  "protocol": "tcp"\n}', 0.75, 1.95, 5.3, 2.9, 21);
  code(s, 'if instruction.operation == "report":\n    return ProbeResult(\n        True, "reported",\n        instruction.message)\nif instruction.operation in {"allow", "deny"}:\n    return adapter.firewall(instruction)\nreturn adapter.check(instruction)', 6.35, 1.95, 6.24, 2.9, 14.5);
  text(s, 'Plano serializado', 1.02, 5.18, 4.85, 0.45, { color: C.cyan, fontSize: 24, bold: true });
  text(s, 'Recorte de uma instrução. O plano completo também preserva a origem no código.', 1.02, 5.8, 4.85, 0.85, { fontSize: 19 });
  text(s, 'Despacho explícito', 6.64, 5.18, 5.3, 0.45, { color: C.purple, fontSize: 24, bold: true });
  text(s, 'Preflight valida o ambiente. Cada ação produz sucesso, status e detalhe.', 6.64, 5.8, 5.3, 0.85, { fontSize: 19 });
  note(s, 'Plano e executor próprios', 'À esquerda está uma projeção dos campos de uma instrução, omitindo source e message para caber. À direita está o despacho de _execute_instruction, reformatado sem mudar sua lógica. Antes do loop, preflight valida todos os alvos. O executor mantém registros por instrução, inclusive quando um adaptador falha. Não existe execução de strings Python nem delegação do fluxo da NetSec a outra linguagem.', ['src/netsec/core/compiler.py', 'src/netsec/runtime.py']);
}

function adapters(pres, icons) {
  const s = base(pres, icons, 'Ambientes de ', 'execução', 'network',
    'O mesmo plano tem efeitos diferentes somente quando o modo é escolhido explicitamente');
  table(s, ['Modo', 'De onde vem o resultado', 'Pode alterar firewall?'], [
    ['simulate', 'Cenário JSON explícito', 'Somente o estado simulado'],
    ['network', 'Sondas TCP / SSH / HTTP(S) locais', 'Não. Rejeita regras no preflight'],
    ['docker', 'Sondas e nftables no laboratório', 'Sim, nos containers autorizados'],
  ], 0.75, 2.05, 11.85, [1.85, 5.5, 4.5], 0.86, 19);
  point(s, icons, 'search', 'Check de porta', 'Comprova uma conexão TCP no endpoint.', 1.03, 5.7, 5.5);
  point(s, icons, 'shield', 'Check de serviço', 'Valida identificação ou resposta do protocolo.', 6.87, 5.7, 5.2, C.purple);
  note(s, 'Ambientes de execução', 'Diferencie resultado simulado de observação real. network não modifica firewall. docker exige inventário, label de propriedade e correspondência entre IP e container. Uma porta aberta não comprova que o serviço é seguro. SSH verifica o banner, HTTP verifica uma resposta HTTP e HTTPS também exige certificado válido para o IP. UDP genérico não é uma sonda suportada, embora regras UDP sejam aceitas.', ['src/netsec/runtime.py', 'src/netsec/services/probes.py', 'src/netsec/services/docker.py']);
}

function editor(pres, icons) {
  const s = base(pres, icons, 'Edição no ', 'VS Code', 'editor',
    'O editor consulta o mesmo compilador, inclusive no texto ainda não salvo');
  panel(s, 0.75, 1.88, 7.4, 4.81);
  code(s, 'port admin = port(22);\n\n// Completion at the cursor:\nadmin   : port', 1.05, 2.18, 6.8, 1.8, 23);
  code(s, 'int broken = true;\n             ^\nE_TYPE', 1.05, 4.52, 6.8, 1.58, 23);
  point(s, icons, 'type', 'Sugestões tipadas', 'Nomes visíveis e palavras-chave.', 8.55, 2.12, 3.95);
  point(s, icons, 'route', 'Navegação', 'Hover e ida à declaração.', 8.55, 3.68, 3.95, C.purple);
  point(s, icons, 'warning', 'Diagnóstico', 'Arquivo, linha e coluna, sem executar rede.', 8.55, 5.23, 3.95);
  note(s, 'Edição no VS Code', 'Abra o exemplo no editor e mostre autocomplete e ir à declaração. Introduza temporariamente int broken = true para mostrar o erro. O quadro representa o conteúdo e a sugestão, não é uma captura de tela. A integração real foi testada no VS Code: completion tipada, navegação e E_TYPE em documento não salvo. A extensão usa APIs diretas do VS Code, não um servidor LSP nesta versão. Reverta a edição de demonstração ao terminar.', ['src/netsec/editor.py', 'editor/vscode/extension.js', 'editor/vscode/test/integration.js', 'docs/validacao-2026-09-18.md'], ['https://code.visualstudio.com/api/language-extensions/programmatic-language-features']);
}

function laboratory(pres, icons) {
  const s = base(pres, icons, 'Laboratório ', 'Linux', 'lab',
    'Três containers em rede interna, sem publicar portas no computador');
  panel(s, 0.8, 2.15, 3.05, 3.23, C.panel);
  circleIcon(s, icons, 'search', 2.0, 2.52, 0.66);
  text(s, 'probe', 1.1, 3.45, 2.45, 0.45, { align: 'center', color: C.white, fontSize: 25, bold: true });
  text(s, '172.30.249.2', 1.02, 4.13, 2.6, 0.5, { align: 'center', fontFace: 'Courier New', fontSize: 21 });
  for (let i = 0; i < 2; i++) {
    const y = 1.98 + i * 2.43;
    panel(s, 7.55, y, 4.97, 1.98);
    circleIcon(s, icons, 'server', 7.87, y + 0.32, 0.64, i ? C.purple : C.cyan);
    text(s, `web0${i + 1}`, 8.77, y + 0.3, 3.2, 0.4, { color: C.white, fontSize: 24, bold: true });
    text(s, `172.30.249.${10 + i}`, 8.77, y + 0.89, 3.25, 0.4, { fontFace: 'Courier New', fontSize: 21 });
    text(s, 'SSH 22, HTTP 80, fixture TCP 23', 7.88, y + 1.5, 4.35, 0.27, { fontSize: 15.5, color: C.quiet });
  }
  arrow(s, 3.88, 3.33, 7.28, 2.95, C.cyan);
  arrow(s, 3.88, 4.38, 7.28, 5.38, C.purple);
  text(s, 'Sondas reais', 4.35, 3.75, 2.7, 0.4, { align: 'center', color: C.white, fontSize: 21 });
  text(s, 'NET_ADMIN apenas nos alvos. nftables filtra dentro dos containers.', 0.95, 6.66, 11.7, 0.36,
    { fontSize: 18, align: 'center' });
  note(s, 'Laboratório Linux', 'Identifique a origem da observação: as sondas saem do probe, não do próprio servidor. Os dois alvos têm nftables e capacidade NET_ADMIN no namespace de rede do container. A porta 23 usa uma fixture TCP em texto simples, não um servidor Telnet completo. O ambiente usa IPs explícitos e não publica portas. O firewall do Windows permaneceu intocado. Este teste usa o kernel Linux do ambiente Docker e comprova comportamento real de pacotes nesse laboratório.', ['lab/compose.yaml', 'lab/Dockerfile', 'lab/server.py', 'docs/laboratorio.md']);
}

function demonstration(pres, icons) {
  const s = base(pres, icons, 'Demonstração ', 'ao vivo', 'terminal',
    'Comandos curtos para acompanhar o código, o erro e o comportamento da rede');
  const commands = [
    ['1', 'Compilar', 'poetry run netsec check examples/02_policy.netsec'],
    ['2', 'Simular', 'poetry run netsec run examples/02_policy.netsec\n  --scenario examples/scenario.json'],
    ['3', 'Rejeitar conflito', 'poetry run netsec check examples/04_rejected.netsec'],
    ['4', 'Testar firewall real', 'poetry run netsec lab-test'],
  ];
  commands.forEach(([number, heading, command], i) => {
    const y = 1.82 + i * 1.23;
    circleIcon(s, icons, i === 2 ? 'warning' : 'play', 0.8, y + 0.2, 0.55, i % 2 ? C.purple : C.cyan);
    text(s, `${number}. ${heading}`, 1.58, y + 0.18, 3.03, 0.55,
      { color: C.white, bold: true, fontSize: 21 });
    code(s, command, 4.8, y, 7.8, 0.94, 15.2);
  });
  note(s, 'Demonstração ao vivo', 'Reserve cerca de 1 minuto e 45 segundos. Antes da fala, inicie o laboratório com docker compose -f lab/compose.yaml up -d e abra o VS Code. Execute check, depois a simulação. No segundo comando, a quebra visual não deve ser copiada como dois comandos separados: use uma única linha. Mostre o código de saída 2 e E_FIREWALL_CONFLICT do exemplo inválido. Rode lab-test para obter evidências novas. O comando redefine apenas regras gerenciadas nos alvos do laboratório e testa a reaplicação. Se a inicialização do Docker consumir o tempo da apresentação, mostre os arquivos de evidência da execução anterior, identificando-os como execução gravada. Não apresente uma simulação como teste real. O roteiro completo está em docs/demonstracao.md.', ['docs/laboratorio.md', 'src/netsec/lab_validation.py', 'examples/02_policy.netsec', 'examples/04_rejected.netsec']);
}

function networkResults(pres, icons) {
  const s = base(pres, icons, 'Resultados da ', 'rede', 'check',
    'Validação real em dois alvos Linux, executada em 18/09/2026');
  table(s, ['Observação', 'Antes', 'Após a política'], [
    ['TCP/23', 'Conexão aceita', 'Timeout em ambos os hosts'],
    ['SSH / TCP 22', 'Identificação SSH recebida', 'Continua acessível'],
    ['HTTP / TCP 80', 'Resposta HTTP válida', 'Continua acessível'],
    ['Mesma regra novamente', 'Primeira aplicação: applied', 'Reaplicação: unchanged'],
  ], 0.75, 1.92, 11.85, [3.0, 4.0, 4.85], 0.69, 19);
  point(s, icons, 'shield', 'Bloqueio observado', 'A regra deny impede novas conexões à porta 23.', 1.02, 5.65, 5.55);
  point(s, icons, 'route', 'Idempotência', 'Reaplicar a mesma política não duplica a regra.', 6.94, 5.65, 5.25, C.purple);
  note(s, 'Resultados da rede', 'Mostre a comparação antes e depois. O teste considera timeout na porta 23 o comportamento esperado do drop aplicado. SSH e HTTP continuam disponíveis. O teste também exige unchanged na segunda aplicação das mesmas regras. A execução local e o job Linux do GitHub Actions tiveram sucesso. Isso valida esse cenário controlado, sem provar compatibilidade com qualquer firewall ou ambiente de produção. O JSON bruto fica em data/processed, fora do Git.', ['docs/validacao-2026-09-18.md', 'src/netsec/lab_validation.py'], [`${REPO}/actions/runs/35370618495`]);
}

function semanticResults(pres, icons) {
  const s = base(pres, icons, 'Avaliação ', 'semântica', 'chart',
    'Eixo B: 25 erros deliberados e 10 controles válidos');
  s.addChart(pres.ChartType.bar, [{ name: 'Resultado esperado',
    labels: ['Erros detectados', 'Controles aceitos'], values: [25, 10] }], {
    x: 0.9, y: 1.88, w: 7.68, h: 4.3,
    catAxisLabelFontFace: 'Calibri', catAxisLabelFontSize: 17, catAxisLabelColor: C.white,
    valAxisLabelFontFace: 'Calibri', valAxisLabelFontSize: 15, valAxisLabelColor: C.muted,
    valAxisMinVal: 0, valAxisMaxVal: 30, valAxisMajorUnit: 10,
    showTitle: true, title: 'Programas com resultado esperado', titleFontFace: 'Calibri',
    titleFontSize: 20, titleColor: C.white,
    chartColors: [C.cyan], showLegend: false, showValue: true,
    dataLabelPosition: 'outEnd', dataLabelFormatCode: '0', dataLabelColor: C.white,
    dataLabelBkgrdColor: C.bg, dataLabelFormatCodeSourceLinked: false,
    dataLabelFontFace: 'Calibri', dataLabelFontSize: 22,
    showCatName: false, showBorder: false, showSerName: false,
    showValAxisTitle: true, valAxisTitle: 'Quantidade de programas',
    valAxisTitleFontFace: 'Calibri', valAxisTitleFontSize: 15, valAxisTitleColor: C.muted,
    catAxisLineShow: false, valAxisLineShow: false,
    valGridLine: { color: C.border, width: 1 }, catGridLine: { style: 'none' },
    chartArea: { fill: { color: C.bg } }, plotArea: { fill: { color: C.bg } },
  });
  panel(s, 9.0, 2.15, 3.15, 3.62, C.panel);
  text(s, '0', 9.3, 2.45, 2.55, 0.95, { fontSize: 60, color: C.green, bold: true, align: 'center' });
  text(s, 'falsos positivos\ne erros que escaparam', 9.35, 3.55, 2.45, 1.0, { fontSize: 21, color: C.white, align: 'center' });
  text(s, 'Neste corpus preparado', 9.35, 4.94, 2.45, 0.45, { fontSize: 16, color: C.quiet, align: 'center' });
  text(s, 'Os casos inválidos passam pelo parser. Acertar este conjunto não prova completude.', 0.95, 6.48, 11.7, 0.5,
    { fontSize: 18.5, align: 'center' });
  note(s, 'Avaliação semântica', 'O experimento separa sintaxe de semântica: cada caso inválido passa pelo parser antes de avaliar a rejeição. São 25 programas com erro deliberado e 10 controles. Todos tiveram o diagnóstico ou aceitação esperados. Cada caso roda dez vezes e o relatório guarda a mediana de tempo, embora o gráfico mostre apenas contagens. O conjunto cobre tipos, fronteiras, escopo, IP/CIDR e conflitos. Zero falhas neste conjunto sintético não estima a precisão em uso real nem prova que todo erro possível é detectado.', ['src/netsec/evaluation.py', 'docs/validacao-2026-09-18.md']);
}

function quality(pres, icons) {
  const s = base(pres, icons, 'Qualidade e ', 'tecnologias', 'check',
    'Resultados do portão de validação do marco acadêmico');
  [['61', 'testes Python', C.cyan], ['4', 'testes Node', C.purple], ['84%', 'cobertura unitária', C.cyan]].forEach(([count, label, color], i) => {
    const x = 0.78 + 4.12 * i;
    panel(s, x, 1.86, 3.55, 2.03);
    text(s, count, x + 0.15, 2.13, 3.25, 0.8, { fontSize: 50, bold: true, color, align: 'center' });
    text(s, label, x + 0.15, 3.13, 3.25, 0.43, { fontSize: 22, color: C.white, align: 'center' });
  });
  table(s, ['Camada', 'Tecnologias e validação'], [
    ['Compilador e executor', 'Python 3.12, Poetry, Pydantic e loguru'],
    ['Qualidade', 'Ruff, mypy estrito, pytest e detector de segredos'],
    ['Editor e integração', 'JavaScript tipado, VS Code, Docker e nftables'],
  ], 0.78, 4.28, 11.8, [3.5, 8.3], 0.59, 18);
  text(s, 'CI aprovado: Windows, Ubuntu e laboratório de rede Linux', 1, 6.82, 11.35, 0.25,
    { fontSize: 16, color: C.green, align: 'center' });
  note(s, 'Qualidade e tecnologias', 'Os 61 testes Python e quatro testes Node são executáveis e passaram novamente durante a preparação. A cobertura unitária registrada é 84% de src, sem contar as integrações separadas. O VS Code também teve um teste real de integração, e o laboratório validou o firewall. Não confunda CI Windows com aplicação do Windows Firewall: o job Windows valida compilador, runtime e editor. O código é organizado em src e as dependências Python são fixadas no lock do Poetry.', ['pyproject.toml', '.github/workflows/ci.yml', 'docs/validacao-2026-09-18.md'], [`${REPO}/actions/runs/35370618495`]);
}

function limitations(pres, icons) {
  const s = base(pres, icons, 'Limites da ', 'versão acadêmica', 'warning',
    'O escopo controlado permite explicar e testar a implementação inteira');
  panel(s, 0.75, 1.88, 5.72, 4.84);
  panel(s, 6.78, 1.88, 5.8, 4.84, C.panel);
  point(s, icons, 'code', 'Linguagem', 'Condições estáticas e declarações imutáveis. Sem funções de usuário ou módulos.', 1.05, 2.18, 5.05);
  point(s, icons, 'search', 'Observações', 'Sondas limitadas de serviço. Sem identificação de vulnerabilidades.', 1.05, 4.39, 5.05, C.purple);
  point(s, icons, 'shield', 'Firewall', 'Validação real no laboratório Linux. Windows nativo ainda não implementado.', 7.09, 2.18, 5.04);
  point(s, icons, 'network', 'Operação distribuída', 'Sem administração remota autenticada, rollback global ou execução autônoma.', 7.09, 4.39, 5.04, C.purple);
  note(s, 'Limites da versão acadêmica', 'Defenda as escolhas de escopo. Tipagem explícita, ausência de módulos e funções mantêm o foco nos requisitos obrigatórios. O compilador apresenta o primeiro erro e ainda não faz recuperação de múltiplos diagnósticos. O firewall Windows e servidores remotos não foram implementados. A sessão Windows atual não está elevada. A automação atual é um programa disparado manualmente; grupos e plays não significam que já existe coordenação distribuída de servidores.', ['README.md', 'docs/especificacao.md', 'docs/evolucao.md']);
}

function conclusion(pres, icons) {
  const s = base(pres, icons, 'Conclusão e ', 'evolução', 'route',
    'Uma linguagem executável com semântica de domínio demonstrável');
  point(s, icons, 'code', 'Entrega acadêmica', 'Código legível, gramática definida, compilador próprio e editor integrado.', 1.02, 2.0, 11.2);
  point(s, icons, 'check', 'Benefício demonstrado', 'Políticas contraditórias são recusadas antes de qualquer ação de rede.', 1.02, 3.58, 11.2, C.purple);
  point(s, icons, 'route', 'Evolução profissional separada', 'Linux nativo primeiro. Depois Windows, acesso remoto e automações operacionais.', 1.02, 5.17, 11.2);
  note(s, 'Conclusão e evolução', 'Conclua retomando o objetivo: a NetSec transforma um programa tipado em verificações e regras observáveis. A entrega acadêmica preserva uma base demonstrável. A branch feat/professional-platform foi separada para evolução futura, ainda sem novos adaptadores. Os resultados esperados dessa evolução são uso por profissionais de redes, políticas com prévia, privilégio explícito, auditoria e testes em servidores. Isso é um plano, não um resultado medido. O artigo, as referências obrigatórias da disciplina e a revisão entre integrantes continuam sendo entregas separadas.', ['README.md', 'docs/evolucao.md', 'docs/entregas.md']);
}

function references(pres, icons) {
  const s = base(pres, icons, 'Referências e ', 'reprodução', 'book');
  const refs = [
    ['Código e especificação da NetSec', REPO, 'docs/especificacao.md e docs/arquitetura.md'],
    ['Evidências do marco acadêmico', `${REPO}/actions/runs/35370618495`, 'docs/validacao-2026-09-18.md'],
    ['Python: endereços IP e redes', 'https://docs.python.org/3.12/library/ipaddress.html', 'Representação e validação de IPv4, IPv6 e CIDR'],
    ['VS Code: recursos para linguagens', 'https://code.visualstudio.com/api/language-extensions/programmatic-language-features', 'Completion, hover, definição e diagnósticos'],
    ['nftables: referência oficial', 'https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes', 'Tabelas, chains, regras e consultas'],
  ];
  refs.forEach(([title, url, description], i) => {
    const y = 1.37 + i * 1.05;
    circleIcon(s, icons, i < 2 ? 'code' : 'book', 0.87, y + 0.05, 0.44, i % 2 ? C.purple : C.cyan);
    text(s, title, 1.55, y, 10.7, 0.39, { fontSize: 23, bold: true, color: C.white, hyperlink: { url } });
    text(s, description, 1.55, y + 0.46, 10.7, 0.35, { fontSize: 18 });
  });
  text(s, 'Links clicáveis nos títulos. Comandos e fontes completos nas notas.', 1.05, 6.8, 11.3, 0.28,
    { fontSize: 15, color: C.quiet, align: 'center' });
  note(s, 'Referências e reprodução', 'Deixe este slide disponível durante a arguição. Os títulos têm links clicáveis. As notas de cada slide identificam os arquivos de implementação que sustentam as afirmações. A referência visual é NetSec Apresentacao_v.pdf, fornecida pela equipe. Os critérios acadêmicos vêm da apresentação oficial atividade_final_apresentacao (1).pptx. Os ícones usam Font Awesome Free via react-icons, licença CC BY 4.0 para os glifos. Estas referências técnicas não substituem as duas referências da bibliografia da disciplina exigidas para o artigo final.', ['README.md', 'docs/entregas.md', 'docs/validacao-2026-09-18.md'], refs.map(item => item[1]).concat(['https://fontawesome.com/license/free']));
}

build().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
