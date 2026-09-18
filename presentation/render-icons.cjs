/** Render licensed Font Awesome glyphs with the reference palette. */
const React = require('react');
const ReactDOMServer = require('react-dom/server');
const sharp = require('sharp');
const fa = require('react-icons/fa6');

const components = Object.freeze({
  shield: fa.FaShieldHalved, network: fa.FaNetworkWired, server: fa.FaServer,
  code: fa.FaCode, tokens: fa.FaList, tree: fa.FaSitemap, type: fa.FaTag,
  scope: fa.FaLayerGroup, warning: fa.FaTriangleExclamation, play: fa.FaPlay,
  editor: fa.FaLaptopCode, lab: fa.FaFlask, terminal: fa.FaTerminal,
  chart: fa.FaChartColumn, check: fa.FaCircleCheck, book: fa.FaBookOpen,
  route: fa.FaRoute, target: fa.FaBullseye, search: fa.FaMagnifyingGlass,
});

async function renderIcons() {
  const images = {};
  for (const [name, Component] of Object.entries(components)) {
    for (const [variant, color] of Object.entries({ dark: '0B1324', light: 'F8FAFC' })) {
      const svg = ReactDOMServer.renderToStaticMarkup(
        React.createElement(Component, { color: `#${color}` }),
      );
      const viewBox = svg.match(/viewBox="([^"]+)"/)[1];
      const [, , width, height] = viewBox.split(' ').map(Number);
      const size = 256;
      const scale = size / Math.max(width, height);
      const inner = svg.replace(/<svg[^>]*>|<\/svg>/g, '');
      const flat = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256" fill="#${color}"><g transform="translate(${(size - width * scale) / 2},${(size - height * scale) / 2}) scale(${scale})">${inner}</g></svg>`;
      const buffer = await sharp(Buffer.from(flat)).png().toBuffer();
      images[`${name}_${variant}`] = `image/png;base64,${buffer.toString('base64')}`;
    }
  }
  return images;
}

module.exports = { renderIcons };
