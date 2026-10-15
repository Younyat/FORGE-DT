import * as THREE from 'three';

/* FORGE-VI · piezas comunes de los cinco nodos. Cada nodo = plinto + caja de cristal + marco de neón + equipo.
   Todo geometría: chaflanes, biselados, teclas sueltas, bornes, rejillas.
   Mallas y materiales nombrados: los nombres viajan al OBJ y al GLB. */

export const W = 1.0, H = 0.92, D = 0.88;
export const Y0 = 0.089;

export const mat = (name, p) => { const m = new THREE.MeshStandardMaterial(p); m.name = name; return m; };

export function palette(accent) {
  const a = new THREE.Color(accent);
  // transmission (real glass refraction) removed on purpose -- this exact
  // project already measured MeshPhysicalMaterial transmission forcing an
  // extra scene-capture render pass per transmissive object, per frame, as
  // expensive enough to visibly drop frames with a dozen+ boxes on screen
  // (see entities.js's own box material). Every scenario here has exactly
  // 5 hosts, each with its own glass shell, always on screen together in
  // the overview -- the same cost class, so it stays off the table here
  // too. Plain transparency reads as "glass" close enough at this scale.
  const glass = new THREE.MeshPhysicalMaterial({
    color: a.clone().lerp(new THREE.Color(0xffffff), 0.55),
    transparent: true, opacity: 0.15,
    roughness: 0.05, metalness: 0, side: THREE.DoubleSide, depthWrite: false,
  });
  glass.name = 'vidrio';
  return {
    glass,
    neon: mat('neon', { color: a.clone().lerp(new THREE.Color(0xffffff), 0.08), emissive: a, emissiveIntensity: 3.2, roughness: 0.3, metalness: 0 }),
    neonBase: mat('neon_base', { color: a, emissive: a, emissiveIntensity: 1.15, roughness: 0.35, metalness: 0 }),
    plinto: mat('plinto_metal', { color: 0x1b1e24, roughness: 0.4, metalness: 0.35 }),
    carcasa: mat('carcasa_grafito', { color: 0x2a2e35, roughness: 0.44, metalness: 0.3 }),
    oscuro: mat('plastico_negro', { color: 0x0f1116, roughness: 0.62, metalness: 0.08 }),
    tecla: mat('tecla', { color: 0x1a1d23, roughness: 0.72, metalness: 0.05 }),
    claro: mat('aluminio', { color: 0x9aa1aa, roughness: 0.36, metalness: 0.38 }),
    acero: mat('acero_niquelado', { color: 0xb9bfc6, roughness: 0.28, metalness: 0.4 }),
    pantalla: mat('pantalla', { color: new THREE.Color(0x080d18).lerp(a, 0.3), emissive: a, emissiveIntensity: 0.8, roughness: 0.18 }),
    ui: mat('ui_grafico', { color: 0x8fa8c8, emissive: 0x6d90ba, emissiveIntensity: 0.32, roughness: 0.4 }),
    uiTenue: mat('ui_grafico_tenue', { color: 0x6f86a4, emissive: 0x4d6b90, emissiveIntensity: 0.18, roughness: 0.45 }),
    led: mat('led', { color: a.clone().lerp(new THREE.Color(0xffffff), 0.2), emissive: a, emissiveIntensity: 2.2, roughness: 0.3 }),
    tela: mat('tela_capucha', { color: 0x0b0c10, roughness: 0.94, metalness: 0 }),
    piel: mat('piel_rostro', { color: 0xf98a84, emissive: 0xf98a84, emissiveIntensity: 0.45, roughness: 0.72, metalness: 0 }),
    gris: mat('gris_siemens', { color: 0x8d949c, roughness: 0.46, metalness: 0.22 }),
    grisOscuro: mat('gris_siemens_oscuro', { color: 0x666c74, roughness: 0.52, metalness: 0.18 }),
    blanco: mat('emblema_blanco', { color: 0xe9edf2, roughness: 0.4, metalness: 0.05 }),
    rojo: mat('led_rojo', { color: 0xff5a4a, emissive: 0xff3a24, emissiveIntensity: 1.8, roughness: 0.3 }),
  };
}

/* ---------- primitivas ---------- */

export const box = (w, h, d, m, name) => {
  const o = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), m); o.name = name; return o;
};
// seg default halved (24 -> 12) -- real performance fix, not cosmetic:
// every node model has dozens of cylinders (neon frame alone is 12 of
// them), and at the box's normal on-screen size the extra roundness
// beyond ~12 sides is not visible, only paid for.
export const cyl = (r, h, m, name, seg = 12, r2 = r) => {
  const o = new THREE.Mesh(new THREE.CylinderGeometry(r, r2, h, seg), m); o.name = name; return o;
};

export function roundedShape(w, h, r) {
  const s = new THREE.Shape();
  const x = w / 2 - r, y = h / 2 - r;
  s.moveTo(-x - r, -y);
  s.lineTo(-x - r, y);
  s.absarc(-x, y, r, Math.PI, Math.PI / 2, true);
  s.lineTo(x, y + r);
  s.absarc(x, y, r, Math.PI / 2, 0, true);
  s.lineTo(x + r, -y);
  s.absarc(x, -y, r, 0, -Math.PI / 2, true);
  s.lineTo(-x, -y - r);
  s.absarc(-x, -y, r, -Math.PI / 2, Math.PI, true);
  return s;
}

/** Placa biselada: w(x) · h(y) · d(z), esquinas de radio r. */
export function plate(w, h, d, r, m, name, bevel = 0.0035) {
  const b = Math.min(bevel, d / 3);
  // curveSegments 6->3, bevelSegments 2->1: real performance fix. This is
  // the single most-called primitive across every model (every key on
  // every keyboard, every UI element on every screen, every panel/plinth
  // piece all go through here) -- its per-call vertex count is what
  // actually dominates the ~317k-triangle, measured-slow full 5-host
  // scene, not the coarser cylinder/sphere primitives. Halving the corner
  // tessellation is not visible at the box's normal on-screen size.
  const geo = new THREE.ExtrudeGeometry(roundedShape(w - 2 * b, h - 2 * b, Math.max(r - b, 0.0008)), {
    depth: d - 2 * b, bevelEnabled: true, bevelThickness: b, bevelSize: b, bevelSegments: 1, curveSegments: 3,
  });
  geo.center();
  const o = new THREE.Mesh(geo, m); o.name = name; return o;
}
/** Placa tumbada: w(x) · d(z) · h(y). */
export function plateFlat(w, d, h, r, m, name, bevel) {
  const o = plate(w, d, h, r, m, name, bevel);
  o.rotation.x = -Math.PI / 2;
  return o;
}

/* ---------- conjuntos reutilizables ---------- */

export function keyGrid(P, cols, rows, cw, gap, name) {
  const g = new THREE.Group(); g.name = name;
  const step = cw + gap;
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    const wide = (r === rows - 1 && c > 2 && c < cols - 4);
    if (wide && c !== 4) continue;
    const kw = wide ? cw * 5 + gap * 4 : cw;
    const k = plateFlat(kw, cw, 0.006, 0.0012, P.tecla, `${name}_tecla_${r + 1}_${c + 1}`, 0.0009);
    k.position.set((c - (cols - 1) / 2) * step + (wide ? cw * 2 : 0), 0.004, (r - (rows - 1) / 2) * step);
    g.add(k);
  }
  return g;
}

export function keyboard(P, name = 'teclado') {
  const g = new THREE.Group(); g.name = name;
  const body = plateFlat(0.345, 0.125, 0.014, 0.005, P.carcasa, name + '_cuerpo');
  body.position.y = 0.007;
  const well = plateFlat(0.325, 0.105, 0.004, 0.004, P.oscuro, name + '_hueco');
  well.position.y = 0.0145;
  const keys = keyGrid(P, 15, 5, 0.0175, 0.0032, name + '_teclas');
  keys.position.y = 0.0155;
  const feet = [-1, 1].map((s, i) => {
    const f = cyl(0.004, 0.004, P.oscuro, `${name}_pie_${i + 1}`, 10);
    f.position.set(s * 0.14, 0.001, -0.05); return f;
  });
  g.add(body, well, keys, ...feet);
  return g;
}

export function mouse(P, name = 'raton') {
  const g = new THREE.Group(); g.name = name;
  const shell = new THREE.Mesh(new THREE.SphereGeometry(0.036, 24, 18, 0, Math.PI * 2, 0, Math.PI / 2), P.carcasa);
  shell.name = name + '_carcasa'; shell.scale.set(1, 0.62, 1.42);
  const bottom = plateFlat(0.052, 0.086, 0.004, 0.02, P.oscuro, name + '_base');
  bottom.position.y = 0.002;
  const wheel = cyl(0.007, 0.004, P.oscuro, name + '_rueda', 14);
  wheel.rotation.z = Math.PI / 2; wheel.position.set(0, 0.024, 0.018);
  const split = box(0.0016, 0.004, 0.04, P.oscuro, name + '_junta');
  split.position.set(0, 0.021, 0.028);
  g.add(shell, bottom, wheel, split);
  g.position.y = 0.004;
  return g;
}

export function monitorPanel(P, w, h, name, uiBuilder) {
  const g = new THREE.Group(); g.name = name;
  const shellBack = plate(w * 0.82, h * 0.78, 0.032, 0.01, P.carcasa, name + '_carcasa_posterior');
  shellBack.position.z = -0.022;
  const frame = plate(w, h, 0.014, 0.007, P.oscuro, name + '_bisel');
  const glassFace = plate(w - 0.018, h - 0.018, 0.004, 0.004, P.pantalla, name + '_cristal');
  glassFace.position.z = 0.008;
  g.add(shellBack, frame, glassFace);
  if (uiBuilder) {
    const ui = uiBuilder(P, w - 0.024, h - 0.024, name + '_interfaz');
    ui.position.z = 0.0115;
    g.add(ui);
  }
  return g;
}

export function tower(P, w, h, d, name = 'torre') {
  const g = new THREE.Group(); g.name = name;
  const body = plate(w, h, d, 0.006, P.carcasa, name + '_chasis');
  body.position.y = h / 2;
  const front = plate(w * 0.94, h * 0.96, 0.008, 0.005, P.oscuro, name + '_frontal');
  front.rotation.y = Math.PI / 2; front.position.set(w / 2 + 0.003, h / 2, 0);
  g.add(body, front);
  for (let i = 0; i < 7; i++) {
    const slat = box(0.006, 0.008, d * 0.6, P.claro, `${name}_rejilla_${i + 1}`);
    slat.position.set(w / 2 + 0.006, h * 0.18 + i * 0.016, 0);
    g.add(slat);
  }
  const bay = box(0.007, 0.018, d * 0.66, P.claro, name + '_bahia_optica');
  bay.position.set(w / 2 + 0.005, h * 0.86, 0);
  const btn = cyl(0.011, 0.008, P.acero, name + '_boton', 20);
  btn.rotation.z = Math.PI / 2; btn.position.set(w / 2 + 0.007, h * 0.72, d * 0.22);
  const ring = new THREE.Mesh(new THREE.TorusGeometry(0.019, 0.0035, 10, 30), P.led);
  ring.name = name + '_anillo_neon'; ring.rotation.y = Math.PI / 2;
  ring.position.set(w / 2 + 0.008, h * 0.72, d * 0.22);
  g.add(bay, btn, ring);
  for (const [sx, sz] of [[-1, -1], [1, -1], [-1, 1], [1, 1]]) {
    const f = cyl(0.008, 0.008, P.oscuro, `${name}_pie_${sx}_${sz}`, 12);
    f.position.set(sx * (w / 2 - 0.02), 0.004, sz * (d / 2 - 0.03));
    g.add(f);
  }
  return g;
}

/* ---------- interfaces en pantalla ---------- */

export function uiEscritorio(P, w, h, name) {
  const g = new THREE.Group(); g.name = name;
  const bar = plate(w, 0.024, 0.003, 0.002, P.ui, name + '_barra_tareas');
  bar.position.y = -h / 2 + 0.012;
  g.add(bar);
  for (let i = 0; i < 6; i++) {
    const ic = plate(0.016, 0.016, 0.003, 0.003, P.ui, `${name}_icono_${i + 1}`);
    ic.position.set(-w / 2 + 0.022, h / 2 - 0.026 - i * 0.032, 0);
    g.add(ic);
  }
  const wave = [0.16, 0.12, 0.09].map((r, i) => {
    const t = new THREE.Mesh(new THREE.TorusGeometry(r, 0.004, 8, 40, Math.PI * 0.8), P.ui);
    t.name = `${name}_fondo_arco_${i + 1}`;
    t.position.set(0.02, -0.01, 0); t.rotation.z = -0.6 + i * 0.12;
    return t;
  });
  g.add(...wave);
  return g;
}

export function uiAtaque(P, w, h, name) {
  const g = new THREE.Group(); g.name = name;
  for (let r = 0; r < 12; r++) {
    const len = 0.05 + ((r * 37) % 11) * 0.018;
    const line = plate(len, 0.007, 0.003, 0.0015, P.led, `${name}_linea_codigo_${r + 1}`);
    line.position.set(-w / 2 + len / 2 + 0.01, h / 2 - 0.016 - r * 0.018, 0);
    g.add(line);
  }
  const tag = plate(0.075, 0.018, 0.003, 0.002, P.led, name + '_etiqueta_attack');
  tag.position.set(w / 2 - 0.05, h / 2 - 0.016, 0);
  g.add(tag);
  return g;
}

export function uiScada(P, w, h, name) {
  const g = new THREE.Group(); g.name = name;
  const title = plate(0.115, 0.03, 0.003, 0.002, P.ui, name + '_titulo');
  title.position.set(-w / 2 + 0.07, h / 2 - 0.024, 0);
  g.add(title);
  for (let i = 0; i < 3; i++) {
    const tank = cyl(0.019, 0.085, P.ui, `${name}_deposito_${i + 1}`, 18);
    tank.position.set(-w / 2 + 0.05 + i * 0.055, -0.01, 0);
    const cap = cyl(0.019, 0.006, P.claro, `${name}_deposito_${i + 1}_tapa`, 18);
    cap.position.set(tank.position.x, 0.036, 0);
    g.add(tank, cap);
  }
  const pipe = plate(0.115, 0.006, 0.003, 0.002, P.ui, name + '_tuberia');
  pipe.position.set(-w / 2 + 0.105, -0.062, 0);
  g.add(pipe);
  for (let i = 0; i < 4; i++) {
    const btn = plate(0.085, 0.026, 0.004, 0.004, P.ui, `${name}_boton_menu_${i + 1}`);
    btn.position.set(w / 2 - 0.055, h / 2 - 0.03 - i * 0.034, 0);
    const dot = cyl(0.005, 0.003, P.led, `${name}_boton_menu_${i + 1}_led`, 10);
    dot.rotation.x = Math.PI / 2;
    dot.position.set(w / 2 - 0.09, btn.position.y, 0.002);
    g.add(btn, dot);
  }
  return g;
}

export function uiSupervision(P, w, h, name) {
  const g = new THREE.Group(); g.name = name;
  const mapBg = plate(w * 0.46, h * 0.56, 0.003, 0.004, P.uiTenue, name + '_panel_mapa');
  mapBg.position.set(-w * 0.25, h * 0.12, 0);
  g.add(mapBg);
  for (let i = 0; i < 5; i++) {
    const gl = plate(w * 0.44, 0.0025, 0.004, 0.001, P.pantalla, `${name}_mapa_paralelo_${i + 1}`);
    gl.position.set(-w * 0.25, h * 0.12 - h * 0.2 + i * h * 0.1, 0.002);
    g.add(gl);
  }
  for (let i = 0; i < 10; i++) {
    const bar = plate(0.014, 0.02 + ((i * 29) % 7) * 0.008, 0.004, 0.002, P.ui, `${name}_barra_${i + 1}`);
    bar.position.set(w * 0.08 + i * 0.019, -h * 0.1 + bar.geometry.boundingBox ? 0 : 0, 0);
    bar.position.y = -h * 0.16 + (0.02 + ((i * 29) % 7) * 0.008) / 2;
    g.add(bar);
  }
  const chart = plate(w * 0.36, h * 0.3, 0.003, 0.004, P.uiTenue, name + '_panel_graficas');
  chart.position.set(w * 0.19, h * 0.24, 0);
  const donut = new THREE.Mesh(new THREE.TorusGeometry(0.028, 0.008, 10, 36), P.led);
  donut.name = name + '_anillo_kpi';
  donut.position.set(w * 0.3, -h * 0.28, 0.002);
  for (let r = 0; r < 8; r++) {
    const row = plate(w * 0.24, 0.005, 0.003, 0.0015, P.ui, `${name}_registro_${r + 1}`);
    row.position.set(-w * 0.2, -h * 0.16 - r * 0.015, 0.001);
    g.add(row);
  }
  g.add(chart, donut);
  return g;
}

/* ---------- plinto, cristal, neón ---------- */

export function plinth(P) {
  const g = new THREE.Group(); g.name = 'plinto';
  const slab = plateFlat(1.16, 1.04, 0.05, 0.02, P.plinto, 'plinto_losa');
  slab.position.y = 0.025;
  const rim = plateFlat(1.19, 1.07, 0.012, 0.022, P.neonBase, 'plinto_borde_neon');
  rim.position.y = 0.046;
  const bevel = plateFlat(1.10, 0.98, 0.03, 0.016, P.oscuro, 'plinto_bisel');
  bevel.position.y = 0.068;
  g.add(slab, rim, bevel);
  return g;
}

export function glassShell(P) {
  const g = new THREE.Group(); g.name = 'caja_cristal';
  const t = 0.012, yc = Y0 + H / 2;
  const front = box(W, H, t, P.glass, 'cristal_frontal'); front.position.set(0, yc, D / 2);
  const back = box(W, H, t, P.glass, 'cristal_posterior'); back.position.set(0, yc, -D / 2);
  const left = box(t, H, D, P.glass, 'cristal_izquierdo'); left.position.set(-W / 2, yc, 0);
  const right = box(t, H, D, P.glass, 'cristal_derecho'); right.position.set(W / 2, yc, 0);
  const top = box(W, t, D, P.glass, 'cristal_superior'); top.position.set(0, Y0 + H, 0);
  const bottom = box(W, t, D, P.glass, 'cristal_inferior'); bottom.position.set(0, Y0, 0);
  g.add(front, back, left, right, top, bottom);
  return g;
}

export function neonFrame(P) {
  const g = new THREE.Group(); g.name = 'marco_neon';
  const r = 0.0085, x = W / 2, z = D / 2, yb = Y0 + 0.004, yt = Y0 + H;
  [[-x, -z], [x, -z], [x, z], [-x, z]].forEach(([px, pz], i) => {
    const c = cyl(r, H, P.neon, `neon_vertical_${i + 1}`, 18);
    c.position.set(px, yb + H / 2, pz); g.add(c);
  });
  [yt, yb].forEach((y, lvl) => {
    const tag = lvl === 0 ? 'sup' : 'inf';
    [-z, z].forEach((pz, i) => {
      const c = cyl(r, W, P.neon, `neon_${tag}_x${i + 1}`, 18);
      c.rotation.z = Math.PI / 2; c.position.set(0, y, pz); g.add(c);
    });
    [-x, x].forEach((px, i) => {
      const c = cyl(r, D, P.neon, `neon_${tag}_z${i + 1}`, 18);
      c.rotation.x = Math.PI / 2; c.position.set(px, y, 0); g.add(c);
    });
  });
  let n = 0;
  for (const px of [-x, x]) for (const pz of [-z, z]) for (const y of [yb, yt]) {
    const s = new THREE.Mesh(new THREE.SphereGeometry(r * 1.25, 16, 12), P.neon);
    s.name = `neon_vertice_${++n}`; s.position.set(px, y, pz); g.add(s);
  }
  return g;
}

