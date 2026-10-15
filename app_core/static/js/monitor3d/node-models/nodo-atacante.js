/* Nodo atacante · figura encapuchada y portátil.
   contenido(P) devuelve solo el equipo; build(color) devuelve el nodo completo
   con plinto, caja de cristal y marco de neón. */

import * as THREE from 'three';
import {
  Y0, palette, box, cyl, plate, plateFlat, keyGrid, keyboard, mouse, monitorPanel, tower,
  uiEscritorio, uiAtaque, uiScada, uiSupervision, plinth, glassShell, neonFrame,
} from './partes-comunes.js';

export function contenido(P) {
    const g = new THREE.Group(); g.name = 'contenido_atacante';

    const laptop = new THREE.Group(); laptop.name = 'portatil';
    const base = plateFlat(0.36, 0.25, 0.016, 0.008, P.carcasa, 'portatil_base');
    base.position.y = 0.008;
    const well = plateFlat(0.30, 0.115, 0.004, 0.004, P.oscuro, 'portatil_hueco_teclas');
    well.position.set(0, 0.016, -0.04);
    const keys = keyGrid(P, 13, 4, 0.019, 0.0035, 'portatil_teclas');
    keys.position.set(0, 0.0175, -0.042);
    const pad = plateFlat(0.10, 0.062, 0.003, 0.004, P.oscuro, 'portatil_trackpad');
    pad.position.set(0, 0.0165, 0.065);
    const hinges = [-1, 1].map((s, i) => {
      const h = cyl(0.008, 0.045, P.oscuro, `portatil_bisagra_${i + 1}`, 14);
      h.rotation.z = Math.PI / 2; h.position.set(s * 0.14, 0.016, -0.118);
      return h;
    });
    const lid = new THREE.Group(); lid.name = 'portatil_tapa';
    const lidShell = plate(0.36, 0.235, 0.011, 0.008, P.carcasa, 'portatil_tapa_carcasa');
    const lidFace = plate(0.342, 0.218, 0.004, 0.005, P.oscuro, 'portatil_bisel_pantalla');
    lidFace.position.z = 0.007;
    const lidScreen = plate(0.318, 0.192, 0.003, 0.003, P.pantalla, 'portatil_pantalla');
    lidScreen.position.z = 0.0105;
    lid.add(lidShell, lidFace, lidScreen, (() => {
      const ui = uiAtaque(P, 0.31, 0.185, 'portatil_interfaz');
      ui.position.z = 0.0135; return ui;
    })());
    lid.position.set(0, 0.13, -0.15);
    lid.rotation.x = 0.2;
    laptop.add(base, well, keys, pad, ...hinges, lid);
    laptop.position.set(0, Y0, 0.13);

    const f = new THREE.Group(); f.name = 'figura_encapuchada';
    const torsoProfile = [];
    for (let i = 0; i <= 10; i++) {
      const t = i / 10;
      torsoProfile.push(new THREE.Vector2(0.245 - 0.085 * t * t - 0.02 * t, t * 0.36));
    }
    // Segment counts on this figure's spheres/lathe/torus were explicit,
    // uncapped overrides well above what a small hooded silhouette needs
    // at normal viewing distance -- cut roughly in half across the board,
    // same "not visible, only paid for" reasoning applied everywhere else
    // this session (partes-comunes.js's shared plate()/cyl() defaults,
    // nodo-caso_forense.js's cables/coil/disk platters).
    const torso = new THREE.Mesh(new THREE.LatheGeometry(torsoProfile, 16), P.tela);
    torso.name = 'figura_torso'; torso.position.set(0, Y0, -0.24); torso.scale.z = 0.85;
    const hoodGeo = new THREE.SphereGeometry(0.145, 16, 11, 0, Math.PI * 2, 0, Math.PI * 0.66);
    const hood = new THREE.Mesh(hoodGeo, P.tela);
    hood.name = 'figura_capucha';
    hood.position.set(0, Y0 + 0.40, -0.245);
    hood.scale.set(1, 1.18, 1.08);
    hood.rotation.x = 0.16;
    const nape = new THREE.Mesh(new THREE.SphereGeometry(0.115, 12, 8), P.tela);
    nape.name = 'figura_capucha_nuca';
    nape.position.set(0, Y0 + 0.335, -0.275);
    nape.scale.set(1.05, 0.95, 0.9);
    const brim = new THREE.Mesh(new THREE.TorusGeometry(0.112, 0.024, 8, 16, Math.PI * 1.1), P.tela);
    brim.name = 'figura_capucha_visera';
    brim.position.set(0, Y0 + 0.345, -0.215);
    brim.rotation.set(-1.28, 0, -Math.PI * 0.05);
    const face = new THREE.Mesh(new THREE.SphereGeometry(0.076, 12, 8), P.piel);
    face.name = 'figura_rostro_sombra';
    face.position.set(0, Y0 + 0.335, -0.205);
    const shoulders = [-1, 1].map((s, i) => {
      const o = new THREE.Mesh(new THREE.SphereGeometry(0.072, 10, 7), P.tela);
      o.name = `figura_hombro_${i + 1}`; o.position.set(s * 0.185, Y0 + 0.30, -0.225);
      o.scale.set(1, 0.85, 1); return o;
    });
    const arms = [];
    [-1, 1].forEach((s, i) => {
      const upper = cyl(0.05, 0.19, P.tela, `figura_brazo_${i + 1}`, 18, 0.044);
      upper.position.set(s * 0.185, Y0 + 0.235, -0.185);
      upper.rotation.set(-0.5, 0, s * 0.18);
      const fore = cyl(0.042, 0.20, P.tela, `figura_antebrazo_${i + 1}`, 18, 0.036);
      fore.position.set(s * 0.155, Y0 + 0.135, -0.045);
      fore.rotation.set(-1.15, 0, s * 0.12);
      const hand = plateFlat(0.062, 0.085, 0.026, 0.012, P.piel, `figura_mano_${i + 1}`);
      hand.position.set(s * 0.115, Y0 + 0.045, 0.075);
      hand.rotation.y = s * 0.2;
      arms.push(upper, fore, hand);
    });
    f.add(torso, hood, nape, brim, face, ...shoulders, ...arms);

    g.add(laptop, f);
    return g;
  }

export function build(accent) {
  const P = palette(accent);
  const g = new THREE.Group();
  g.name = 'nodo_atacante';
  g.add(plinth(P), contenido(P), glassShell(P), neonFrame(P));
  return g;
}
