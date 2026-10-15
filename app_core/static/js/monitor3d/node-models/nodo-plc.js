/* Nodo PLC · rack modular tipo S7-1500 sobre carril DIN.
   contenido(P) devuelve solo el equipo; build(color) devuelve el nodo completo
   con plinto, caja de cristal y marco de neón. */

import * as THREE from 'three';
import {
  Y0, palette, box, cyl, plate, plateFlat, plinth, glassShell, neonFrame,
} from './partes-comunes.js';

const YB = Y0 + 0.055;   // base del rack
const MH = 0.52;         // altura de módulo
const MD = 0.30;         // profundidad de módulo
const ZF = MD / 2;       // cara frontal

function railProfile(P) {
  const s = new THREE.Shape();
  s.moveTo(-0.028, 0); s.lineTo(-0.028, 0.008); s.lineTo(-0.012, 0.008);
  s.lineTo(-0.012, 0.034); s.lineTo(0.012, 0.034); s.lineTo(0.012, 0.008);
  s.lineTo(0.028, 0.008); s.lineTo(0.028, 0); s.closePath();
  const geo = new THREE.ExtrudeGeometry(s, { depth: 0.80, bevelEnabled: false });
  geo.center();
  const m = new THREE.Mesh(geo, P.acero);
  m.name = 'carril_din';
  m.rotation.y = Math.PI / 2;
  return m;
}

function cpuModule(P) {
  const g = new THREE.Group(); g.name = 'modulo_cpu';
  const w = 0.20;
  const body = plate(w, MH, MD, 0.007, P.gris, 'cpu_chasis');
  body.position.y = MH / 2;
  const face = plate(w - 0.016, MH - 0.10, 0.008, 0.005, P.grisOscuro, 'cpu_frontal');
  face.position.set(0, MH / 2 - 0.005, ZF + 0.003);
  g.add(body, face);

  // tapas de bornes arriba y abajo
  [MH - 0.035, 0.035].forEach((y, i) => {
    const c = plate(w - 0.006, 0.062, MD * 0.22, 0.005, P.gris, `cpu_tapa_bornes_${i + 1}`);
    c.position.set(0, y, ZF - 0.02);
    g.add(c);
  });

  // pantalla
  const bezel = plate(0.125, 0.10, 0.008, 0.004, P.oscuro, 'cpu_pantalla_bisel');
  bezel.position.set(0, MH * 0.66, ZF + 0.008);
  const screen = plate(0.108, 0.082, 0.004, 0.003, P.pantalla, 'cpu_pantalla');
  screen.position.set(0, MH * 0.66, ZF + 0.013);
  g.add(bezel, screen);

  // teclado de navegación: cuatro flechas y tecla central
  const pad = new THREE.Group(); pad.name = 'cpu_teclado';
  const centro = plate(0.026, 0.026, 0.008, 0.004, P.grisOscuro, 'cpu_tecla_centro');
  pad.add(centro);
  [[0, 0.032, 'arriba'], [0, -0.032, 'abajo'], [-0.034, 0, 'izquierda'], [0.034, 0, 'derecha']]
    .forEach(([x, y, nombre]) => {
      const k = plate(0.026, 0.026, 0.008, 0.004, P.grisOscuro, `cpu_tecla_${nombre}`);
      k.position.set(x, y, 0);
      const tri = new THREE.Mesh(new THREE.ConeGeometry(0.007, 0.009, 3), P.blanco);
      tri.name = `cpu_flecha_${nombre}`;
      tri.rotation.x = Math.PI / 2;
      tri.rotation.y = 0;
      tri.rotation.z = Math.atan2(-x, y);
      tri.position.set(x, y, 0.006);
      pad.add(k, tri);
    });
  pad.position.set(0, MH * 0.34, ZF + 0.008);
  g.add(pad);

  // teclas ESC y OK
  [[-0.055, 'esc'], [0.055, 'ok']].forEach(([x, nombre]) => {
    const k = plate(0.03, 0.014, 0.008, 0.003, P.grisOscuro, `cpu_tecla_${nombre}`);
    k.position.set(x, MH * 0.34 - 0.062, ZF + 0.008);
    const lbl = plate(0.018, 0.005, 0.003, 0.0015, P.blanco, `cpu_etiqueta_${nombre}`);
    lbl.position.set(x, MH * 0.34 - 0.062, ZF + 0.013);
    g.add(k, lbl);
  });

  // franja de marca y LEDs de estado
  const marca = plate(0.10, 0.018, 0.004, 0.002, P.blanco, 'cpu_franja_marca');
  marca.position.set(0, MH * 0.82, ZF + 0.008);
  g.add(marca);
  for (let i = 0; i < 4; i++) {
    const led = plate(0.014, 0.006, 0.005, 0.0015, P.led, `cpu_led_${i + 1}`);
    led.position.set(-0.052 + (i % 2) * 0.104, MH * 0.89 - Math.floor(i / 2) * 0.013, ZF + 0.008);
    g.add(led);
  }

  // puerto Profinet en el flanco inferior
  const port = plate(0.05, 0.034, 0.014, 0.003, P.acero, 'cpu_puerto_profinet');
  port.position.set(0, MH * 0.14, ZF + 0.008);
  const hole = plate(0.038, 0.024, 0.006, 0.002, P.oscuro, 'cpu_puerto_hueco');
  hole.position.set(0, MH * 0.14, ZF + 0.014);
  g.add(port, hole);
  return g;
}

function ioModule(P, n) {
  const g = new THREE.Group(); g.name = `modulo_io_${n}`;
  const w = 0.105;
  const body = plate(w, MH, MD, 0.005, P.gris, `modulo_io_${n}_chasis`);
  body.position.y = MH / 2;
  const cover = plate(w - 0.012, MH - 0.13, 0.01, 0.004, P.grisOscuro, `modulo_io_${n}_tapa_frontal`);
  cover.position.set(0, MH / 2 - 0.008, ZF + 0.004);
  g.add(body, cover);

  // rejilla de ventilación de la tapa -- 16 lamas por módulo x 5 módulos
  // (80 llamadas a plate(), cada una una ExtrudeGeometry con bisel) fue el
  // mayor contribuyente real al recuento de triángulos del PLC (43.8k,
  // el modelo más pesado de los 6, medido esta sesión). Cortado a 7 lamas
  // más altas que siguen cubriendo la misma franja visual de la tapa --
  // no se distingue a la distancia normal de la caja, solo se pagaba.
  for (let i = 0; i < 7; i++) {
    const slat = plate(w - 0.028, 0.017, 0.005, 0.0015, P.gris, `modulo_io_${n}_lama_${i + 1}`);
    slat.position.set(0, MH * 0.19 + i * 0.0405, ZF + 0.0095);
    g.add(slat);
  }

  // borneras arriba y abajo con tornillos
  [MH - 0.032, 0.032].forEach((y, b) => {
    const blk = plate(w - 0.004, 0.056, MD * 0.24, 0.004, P.gris, `modulo_io_${n}_bornera_${b + 1}`);
    blk.position.set(0, y, ZF - 0.022);
    g.add(blk);
    for (let s = 0; s < 3; s++) {
      const screw = cyl(0.006, 0.006, P.acero, `modulo_io_${n}_tornillo_${b + 1}_${s + 1}`, 10);
      screw.rotation.x = Math.PI / 2;
      screw.position.set(-0.028 + s * 0.028, y, ZF + 0.006);
      g.add(screw);
    }
  });

  // columna de LEDs y etiqueta
  for (let l = 0; l < 8; l++) {
    const led = plate(0.012, 0.005, 0.005, 0.0012, P.led, `modulo_io_${n}_led_${l + 1}`);
    led.position.set(-0.018 + (l % 2) * 0.036, MH * 0.86 - Math.floor(l / 2) * 0.013, ZF + 0.0095);
    g.add(led);
  }
  const tag = plate(0.05, 0.014, 0.004, 0.002, P.blanco, `modulo_io_${n}_etiqueta`);
  tag.position.set(0, MH * 0.115, ZF + 0.0095);
  g.add(tag);
  return g;
}

export function contenido(P) {
  const g = new THREE.Group(); g.name = 'contenido_plc';

  const rail = railProfile(P);
  rail.position.set(0, YB + MH + 0.02, -0.055);
  const backPlate = plate(0.80, 0.035, 0.012, 0.004, P.acero, 'placa_montaje');
  backPlate.position.set(0, YB + MH + 0.036, -0.145);
  g.add(rail, backPlate);

  const cpu = cpuModule(P);
  cpu.position.set(-0.262, YB, 0);
  g.add(cpu);

  for (let m = 0; m < 5; m++) {
    const io = ioModule(P, m + 1);
    io.position.set(-0.108 + m * 0.108, YB, 0);
    g.add(io);
  }

  // patas de apoyo del rack
  for (const sx of [-0.30, 0.28]) {
    const pie = plateFlat(0.07, MD * 0.8, 0.012, 0.004, P.grisOscuro, `rack_pie_${sx < 0 ? 1 : 2}`);
    pie.position.set(sx, YB - 0.006, -0.02);
    g.add(pie);
  }
  return g;
}

export function build(accent) {
  const P = palette(accent);
  const g = new THREE.Group();
  g.name = 'nodo_plc';
  g.add(plinth(P), contenido(P), glassShell(P), neonFrame(P));
  return g;
}
