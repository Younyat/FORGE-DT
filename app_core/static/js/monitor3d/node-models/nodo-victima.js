/* Nodo víctima · PC de sobremesa comprometido.
   contenido(P) devuelve solo el equipo; build(color) devuelve el nodo completo
   con plinto, caja de cristal y marco de neón. */

import * as THREE from 'three';
import {
  Y0, palette, box, cyl, plate, plateFlat, keyGrid, keyboard, mouse, monitorPanel, tower,
  uiEscritorio, uiAtaque, uiScada, uiSupervision, plinth, glassShell, neonFrame,
} from './partes-comunes.js';

export function contenido(P) {
    const g = new THREE.Group(); g.name = 'contenido_victima';
    const mon = monitorPanel(P, 0.46, 0.30, 'monitor', uiEscritorio);
    mon.position.set(-0.085, Y0 + 0.365, -0.09);
    mon.rotation.y = 0.16;
    const neck = cyl(0.022, 0.14, P.claro, 'monitor_cuello', 20, 0.028);
    neck.position.set(-0.085, Y0 + 0.145, -0.085);
    const joint = cyl(0.026, 0.03, P.oscuro, 'monitor_rotula', 18);
    joint.rotation.z = Math.PI / 2; joint.position.set(-0.085, Y0 + 0.215, -0.085);
    const foot = plateFlat(0.22, 0.15, 0.014, 0.02, P.carcasa, 'monitor_base');
    foot.position.set(-0.085, Y0 + 0.007, -0.075);

    const kb = keyboard(P); kb.position.set(-0.05, Y0, 0.235); kb.rotation.y = 0.05;
    const ms = mouse(P); ms.position.set(0.17, Y0, 0.245);
    const tw = tower(P, 0.165, 0.42, 0.40); tw.position.set(0.31, Y0, -0.04); tw.rotation.y = -0.1;
    g.add(mon, joint, neck, foot, kb, ms, tw);
    return g;
  }

export function build(accent) {
  const P = palette(accent);
  const g = new THREE.Group();
  g.name = 'nodo_victima';
  g.add(plinth(P), contenido(P), glassShell(P), neonFrame(P));
  return g;
}
