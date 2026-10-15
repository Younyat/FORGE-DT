/* Nodo forense · estación forense de campo en maletín rígido.
   Tapa superior: solo el monitor con el escritorio. Base inferior: teclado, dos discos
   abiertos, tarjeta puente, cableado, pantalla táctil y regleta de conectores.
   contenido(P) devuelve solo el equipo; build(color) el nodo completo. */

import * as THREE from 'three';
import {
  Y0, palette, mat, box, cyl, plate, plateFlat, plinth, glassShell, neonFrame,
} from './partes-comunes.js';

const negro = mat('maletin_polimero_negro', { color: 0x14161a, roughness: 0.72, metalness: 0.06 });
const negroMate = mat('maletin_polimero_mate', { color: 0x0d0f12, roughness: 0.88, metalness: 0.03 });
const azul = mat('panel_anodizado_azul', { color: 0x1c3f8c, roughness: 0.38, metalness: 0.35 });
const azulOsc = mat('panel_azul_oscuro', { color: 0x12295c, roughness: 0.45, metalness: 0.3 });
const plata = mat('aluminio_pulido', { color: 0xc3c9d0, roughness: 0.24, metalness: 0.62 });
const plato = mat('plato_disco', { color: 0xe8edf3, emissive: 0x6d7887, emissiveIntensity: 0.22, roughness: 0.16, metalness: 0.6 });
const blancoUI = mat('ventana_ui', { color: 0xf1f3f7, emissive: 0xdfe6f0, emissiveIntensity: 0.38, roughness: 0.4 });
const azulUI = mat('barra_titulo_ui', { color: 0x2f5fb0, emissive: 0x2a54a0, emissiveIntensity: 0.4, roughness: 0.42 });
const grisUI = mat('texto_ui', { color: 0x8892a2, roughness: 0.5 });
const cableMat = mat('cable_gris', { color: 0x565d66, roughness: 0.66, metalness: 0.12 });

/* ---------- pantalla del escritorio (va en la tapa) ---------- */

function pantallaEscritorio(P, w, h, name = 'monitor_forense') {
  const g = new THREE.Group(); g.name = name;
  const bezel = plate(w + 0.036, h + 0.036, 0.022, 0.006, negroMate, name + '_bisel');
  const face = plate(w, h, 0.006, 0.002, blancoUI, name + '_lcd');
  face.position.z = 0.013;
  g.add(bezel, face);

  const win = (n, x, y, ww, hh) => {
    const c = new THREE.Group(); c.name = `${name}_ventana_${n}`;
    const edge = plate(ww + 0.005, hh + 0.005, 0.003, 0.002, grisUI, `${name}_ventana_${n}_marco`);
    edge.position.z = -0.002;
    const body = plate(ww, hh, 0.004, 0.002, blancoUI, `${name}_ventana_${n}_fondo`);
    const bar = plate(ww, 0.018, 0.005, 0.002, azulUI, `${name}_ventana_${n}_titulo`);
    bar.position.set(0, hh / 2 - 0.009, 0.001);
    c.add(edge, body, bar);
    const rows = Math.max(1, Math.floor((hh - 0.034) / 0.014));
    for (let i = 0; i < rows; i++) {
      const lw = ww * (0.42 + ((i * 17) % 5) * 0.11);
      const ln = plate(lw, 0.005, 0.005, 0.001, grisUI, `${name}_ventana_${n}_linea_${i + 1}`);
      ln.position.set(-ww / 2 + lw / 2 + 0.007, hh / 2 - 0.030 - i * 0.014, 0.002);
      c.add(ln);
    }
    c.position.set(x, y, 0.017);
    return c;
  };
  g.add(win('principal', -0.062, 0.020, 0.235, 0.205));
  g.add(win('registro', 0.128, 0.040, 0.115, 0.165));
  g.add(win('progreso', -0.062, -0.112, 0.190, 0.055));

  const taskbar = plate(w, 0.019, 0.005, 0.001, grisUI, name + '_barra_tareas');
  taskbar.position.set(0, -h / 2 + 0.010, 0.017);
  const start = plate(0.044, 0.013, 0.005, 0.002, azulUI, name + '_boton_inicio');
  start.position.set(-w / 2 + 0.028, -h / 2 + 0.010, 0.019);
  g.add(taskbar, start);
  for (let i = 0; i < 5; i++) {
    const ic = plate(0.016, 0.016, 0.005, 0.003, grisUI, `${name}_icono_escritorio_${i + 1}`);
    ic.position.set(-w / 2 + 0.024, h / 2 - 0.026 - i * 0.030, 0.017);
    g.add(ic);
  }
  return g;
}

/* ---------- disco duro abierto (platos a la vista) ---------- */

function discoAbierto(P, name) {
  const g = new THREE.Group(); g.name = name;
  const base = plate(0.150, 0.128, 0.022, 0.010, plata, name + '_bastidor');
  const well = plate(0.112, 0.092, 0.010, 0.006, negroMate, name + '_hueco');
  well.position.z = 0.009;
  // Segment counts here were explicit overrides well above cyl()'s own
  // (already-reduced) default of 12 -- a spinning disc platter this small
  // on screen doesn't need 48-gon roundness. Cut to match the general
  // "not visible at normal viewing distance, only paid for" reasoning
  // already applied project-wide (see partes-comunes.js).
  const disc = cyl(0.049, 0.006, plato, name + '_plato', 20);
  disc.rotation.x = Math.PI / 2;
  disc.position.set(-0.008, 0, 0.016);
  const hub = cyl(0.013, 0.010, plata, name + '_buje', 12);
  hub.rotation.x = Math.PI / 2; hub.position.set(-0.008, 0, 0.019);
  const ring = new THREE.Mesh(new THREE.TorusGeometry(0.020, 0.0025, 6, 16), P.grisOscuro);
  ring.name = name + '_anillo_buje'; ring.position.set(-0.008, 0, 0.021);
  const pivot = cyl(0.009, 0.012, P.grisOscuro, name + '_pivote_actuador', 10);
  pivot.rotation.x = Math.PI / 2; pivot.position.set(0.050, -0.036, 0.018);
  const arm = plate(0.062, 0.013, 0.005, 0.003, plata, name + '_brazo_actuador');
  arm.position.set(0.024, -0.020, 0.021); arm.rotation.z = 0.55;
  const magnet = plate(0.036, 0.024, 0.008, 0.004, P.grisOscuro, name + '_iman_bobina');
  magnet.position.set(0.048, -0.038, 0.014);
  for (let i = 0; i < 4; i++) {
    const s = cyl(0.0035, 0.004, plata, `${name}_tornillo_${i + 1}`, 10);
    s.rotation.x = Math.PI / 2;
    s.position.set((i % 2 ? 1 : -1) * 0.066, (i < 2 ? 1 : -1) * 0.055, 0.012);
    g.add(s);
  }
  const conn = box(0.030, 0.008, 0.008, P.claro, name + '_conector');
  conn.position.set(-0.040, -0.066, 0.006);
  g.add(base, well, disc, hub, ring, pivot, arm, magnet, conn);
  g.rotation.x = -Math.PI / 2; // tumbado sobre la bandeja
  return g;
}

/* ---------- teclado tumbado en la bandeja ---------- */

function tecladoBandeja(P, name = 'teclado_empotrado') {
  const g = new THREE.Group(); g.name = name;
  const tray = plateFlat(0.360, 0.132, 0.014, 0.005, negroMate, name + '_bandeja');
  tray.position.y = 0.007;
  g.add(tray);
  const cols = 15, rows = 5, kw = 0.0195, gap = 0.0035, step = kw + gap;
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    const wide = r === rows - 1 && c > 3 && c < cols - 5;
    if (wide && c !== 5) continue;
    const w = wide ? kw * 4 + gap * 3 : kw;
    const k = plateFlat(w, 0.017, 0.006, 0.0015, P.tecla, `${name}_tecla_${r + 1}_${c + 1}`, 0.0009);
    k.position.set((c - (cols - 1) / 2) * step + (wide ? kw * 1.5 : 0), 0.016, -0.047 + r * 0.0215);
    g.add(k);
  }
  return g;
}

/* ---------- bandeja inferior: discos, puente, teclado, táctil, cableado ---------- */

function bandeja(P, W, D, yTop) {
  const g = new THREE.Group(); g.name = 'bandeja_trabajo';
  const face = plateFlat(W - 0.075, D - 0.075, 0.014, 0.010, azul, 'bandeja_panel_azul');
  face.position.y = yTop;
  const border = plateFlat(W - 0.048, D - 0.048, 0.010, 0.012, azulOsc, 'bandeja_marco');
  border.position.y = yTop - 0.008;
  g.add(border, face);

  const y = yTop + 0.007;
  const d1 = discoAbierto(P, 'disco_forense_origen'); d1.position.set(-0.190, y, -0.140);
  const d2 = discoAbierto(P, 'disco_forense_destino'); d2.position.set(0.190, y, -0.140);
  g.add(d1, d2);

  const pcb = plateFlat(0.098, 0.074, 0.010, 0.003, azulOsc, 'tarjeta_puente');
  pcb.position.set(0, y + 0.004, -0.140);
  g.add(pcb);
  [0xe0443a, 0xf0b429, 0x3f8fe0, 0x35c07a, 0xe0e4ea].forEach((c, i) => {
    const m = mat(`puente_color_${i + 1}`, { color: c, roughness: 0.5, metalness: 0.1 });
    const w = cyl(0.0022, 0.064, m, `puente_${i + 1}`, 8);
    w.rotation.x = Math.PI / 2;
    w.rotation.z = -0.22 + i * 0.11;
    w.position.set(-0.016 + i * 0.008, y + 0.016, -0.118);
    g.add(w);
  });
  for (let i = 0; i < 6; i++) {
    const pin = cyl(0.0014, 0.010, plata, `tarjeta_puente_pin_${i + 1}`, 6);
    pin.rotation.x = Math.PI / 2;
    pin.position.set(-0.020 + i * 0.008, y + 0.012, -0.172);
    g.add(pin);
  }

  const kb = tecladoBandeja(P); kb.position.set(-0.085, y, 0.075);
  g.add(kb);
  const pad = plateFlat(0.100, 0.090, 0.018, 0.006, negroMate, 'panel_tactil_bisel');
  pad.position.set(0.205, y + 0.009, 0.072);
  const padScr = plateFlat(0.076, 0.064, 0.006, 0.003, P.pantalla, 'panel_tactil_pantalla');
  padScr.position.set(0.205, y + 0.020, 0.072);
  g.add(pad, padScr);

  const strip = plateFlat(0.600, 0.046, 0.012, 0.004, azulOsc, 'regleta_conectores');
  strip.position.set(0, y + 0.004, 0.190);
  g.add(strip);
  for (let i = 0; i < 6; i++) {
    const p = box(0.028, 0.012, 0.014, plata, `conector_${i + 1}`);
    p.position.set(-0.22 + i * 0.058, y + 0.012, 0.190);
    g.add(p);
  }
  for (let i = 0; i < 4; i++) {
    const led = cyl(0.0035, 0.006, i === 0 ? P.rojo : P.led, `piloto_${i + 1}`, 10);
    led.position.set(0.180 + i * 0.020, y + 0.012, 0.190);
    g.add(led);
  }

  /* cables: datos hacia cada disco y un lazo de alimentación por la izquierda.
     tubularSegments/radiusSegments cortados (40,9 -> 16,6): un cable de
     fondo no necesita ese nivel de redondez, y son 3 tubos + una bobina --
     el mismo razonamiento de "no se nota a la distancia normal, solo se
     paga" ya aplicado al resto del modelo. */
  const tube = (pts, r, n) => {
    const t = new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts.map(p => new THREE.Vector3(...p))), 16, r, 6, false), cableMat);
    t.name = n; return t;
  };
  g.add(tube([[-0.052, y + 0.010, -0.140], [-0.090, y + 0.040, -0.120], [-0.140, y + 0.030, -0.088], [-0.152, y + 0.012, -0.078]], 0.006, 'cable_datos_origen'));
  g.add(tube([[0.052, y + 0.010, -0.140], [0.090, y + 0.040, -0.120], [0.140, y + 0.030, -0.088], [0.152, y + 0.012, -0.078]], 0.006, 'cable_datos_destino'));
  g.add(tube([[-0.300, y + 0.010, 0.170], [-0.330, y + 0.060, 0.070], [-0.300, y + 0.070, -0.060], [-0.240, y + 0.030, -0.170], [-0.190, y + 0.016, -0.205]], 0.009, 'cable_alimentacion'));
  const coil = new THREE.Mesh(new THREE.TorusGeometry(0.042, 0.008, 6, 16), cableMat);
  coil.name = 'cable_enrollado'; coil.rotation.x = Math.PI / 2;
  coil.position.set(0.300, y + 0.010, -0.040);
  g.add(coil);
  return g;
}

/* ---------- maletín ---------- */

function maletin(P) {
  const g = new THREE.Group(); g.name = 'maletin_forense';
  const W = 0.70, D = 0.50, HB = 0.135;

  /* base */
  const body = plate(W, HB, D, 0.026, negro, 'maletin_base');
  body.position.y = HB / 2;
  g.add(body);
  const rim = plateFlat(W + 0.012, D + 0.012, 0.016, 0.026, negroMate, 'maletin_base_labio');
  rim.position.y = HB - 0.004;
  g.add(rim);
  for (const sx of [-1, 1]) for (const sz of [-1, 1]) {
    const bump = plate(0.055, HB + 0.012, 0.075, 0.014, negroMate, `maletin_esquinera_${sx}_${sz}`);
    bump.position.set(sx * (W / 2 - 0.024), HB / 2, sz * (D / 2 - 0.030));
    g.add(bump);
  }
  for (const sx of [-1, 1]) {
    const latch = plate(0.072, 0.050, 0.030, 0.008, negroMate, `maletin_pestillo_${sx < 0 ? 'izq' : 'der'}`);
    latch.position.set(sx * 0.175, HB - 0.022, D / 2 + 0.010);
    const pin = cyl(0.007, 0.052, plata, `maletin_pasador_${sx < 0 ? 'izq' : 'der'}`, 12);
    pin.rotation.z = Math.PI / 2;
    pin.position.set(sx * 0.175, HB - 0.006, D / 2 + 0.022);
    g.add(latch, pin);
  }
  const handle = new THREE.Mesh(new THREE.TorusGeometry(0.058, 0.011, 6, 14, Math.PI), negroMate);
  handle.name = 'maletin_asa';
  handle.rotation.set(Math.PI / 2, 0, 0);
  handle.position.set(0, HB * 0.55, D / 2 + 0.028);
  g.add(handle);
  for (const sx of [-1, 1]) {
    const h = cyl(0.011, 0.062, negroMate, `maletin_bisagra_${sx < 0 ? 'izq' : 'der'}`, 14);
    h.rotation.z = Math.PI / 2;
    h.position.set(sx * 0.20, HB - 0.006, -D / 2 - 0.008);
    g.add(h);
  }

  g.add(bandeja(P, W, D, HB + 0.004));

  /* tapa: solo la pantalla */
  const lid = new THREE.Group(); lid.name = 'maletin_tapa';
  lid.position.set(0, HB - 0.006, -D / 2 - 0.008);
  lid.rotation.x = -0.20;
  const HL = 0.545;
  const shell = plate(W, HL, 0.060, 0.026, negro, 'maletin_tapa_carcasa');
  shell.position.set(0, HL / 2, -0.014);
  const inner = plate(W - 0.060, HL - 0.060, 0.030, 0.016, negroMate, 'maletin_tapa_interior');
  inner.position.set(0, HL / 2, 0.012);
  lid.add(shell, inner);
  const mon = pantallaEscritorio(P, 0.520, 0.375);
  mon.position.set(0, HL / 2 + 0.010, 0.026);
  lid.add(mon);
  const emblema = plate(0.078, 0.020, 0.006, 0.003, P.blanco, 'emblema_fabricante');
  emblema.position.set(0.245, 0.048, 0.026);
  lid.add(emblema);
  for (const sx of [-1, 1]) {
    const clip = plate(0.048, 0.030, 0.026, 0.006, plata, `maletin_tapa_gancho_${sx < 0 ? 'izq' : 'der'}`);
    clip.position.set(sx * 0.175, 0.026, 0.040);
    lid.add(clip);
  }
  g.add(lid);
  return g;
}

export function contenido(P) {
  const g = new THREE.Group(); g.name = 'contenido_forense';
  const c = maletin(P);
  c.position.set(0, Y0, 0.04);
  c.rotation.y = 0.06;
  g.add(c);
  return g;
}

export function build(accent) {
  const P = palette(accent);
  const g = new THREE.Group();
  g.name = 'nodo_forense';
  g.add(plinth(P), contenido(P), glassShell(P), neonFrame(P));
  return g;
}
