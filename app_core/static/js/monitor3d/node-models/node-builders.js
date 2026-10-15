/* Índice de los objetos. Cada nodo vive en su propio archivo:
   nodo-atacante.js · nodo-victima.js · nodo-plc.js · nodo-fuxa.js · nodo-monitor.js ·
   nodo-caso_forense.js (estación forense de campo, usada para la caja de "case", no de host).
   Las piezas compartidas (plinto, cristal, neón, teclados, pantallas, torres)
   están en partes-comunes.js. */

import { build as atacante } from './nodo-atacante.js';
import { build as victima } from './nodo-victima.js';
import { build as plc } from './nodo-plc.js';
import { build as fuxa } from './nodo-fuxa.js';
import { build as monitor } from './nodo-monitor.js';
import { build as forense } from './nodo-caso_forense.js';

export const NODOS = { atacante, victima, plc, fuxa, monitor, forense };

export function buildNode(kind, accent) {
  return NODOS[kind](accent);
}
