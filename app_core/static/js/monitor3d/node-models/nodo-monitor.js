/* Nodo monitor · puesto de supervisión.
   contenido(P) devuelve solo el equipo; build(color) devuelve el nodo completo
   con plinto, caja de cristal y marco de neón. */

import * as THREE from 'three';
import {
  Y0, palette, box, cyl, plate, plateFlat, keyGrid, keyboard, mouse, monitorPanel, tower,
  uiEscritorio, uiAtaque, uiScada, uiSupervision, plinth, glassShell, neonFrame,
} from './partes-comunes.js';

export function contenido(P) {
    const g = new THREE.Group(); g.name = 'contenido_monitor';
    const mon = monitorPanel(P, 0.62, 0.30, 'monitor_ancho', uiSupervision);
    mon.position.set(-0.04, Y0 + 0.38, -0.10);
    mon.rotation.y = 0.1;
    const arm = plate(0.05, 0.19, 0.028, 0.008, P.claro, 'monitor_brazo');
    arm.position.set(-0.04, Y0 + 0.155, -0.095);
    const hinge = cyl(0.025, 0.036, P.oscuro, 'monitor_rotula', 18);
    hinge.rotation.z = Math.PI / 2; hinge.position.set(-0.04, Y0 + 0.245, -0.095);
    const foot = plateFlat(0.26, 0.17, 0.013, 0.022, P.claro, 'monitor_base');
    foot.position.set(-0.04, Y0 + 0.0065, -0.085);

    const kb = keyboard(P); kb.position.set(-0.07, Y0, 0.225); kb.rotation.y = 0.04;
    const ms = mouse(P); ms.position.set(0.155, Y0, 0.235);
    const pc = tower(P, 0.115, 0.28, 0.25, 'mini_pc'); pc.position.set(0.335, Y0, -0.03); pc.rotation.y = -0.12;
    g.add(mon, hinge, arm, foot, kb, ms, pc);
    return g;
  }

export function build(accent) {
  const P = palette(accent);
  const g = new THREE.Group();
  g.name = 'nodo_monitor';
  g.add(plinth(P), contenido(P), glassShell(P), neonFrame(P));
  return g;
}
