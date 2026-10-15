/* Nodo FUXA · panel HMI/SCADA.
   contenido(P) devuelve solo el equipo; build(color) devuelve el nodo completo
   con plinto, caja de cristal y marco de neón. */

import * as THREE from 'three';
import {
  Y0, palette, box, cyl, plate, plateFlat, keyGrid, keyboard, mouse, monitorPanel, tower,
  uiEscritorio, uiAtaque, uiScada, uiSupervision, plinth, glassShell, neonFrame,
} from './partes-comunes.js';

export function contenido(P) {
    const g = new THREE.Group(); g.name = 'contenido_fuxa';
    const hmi = new THREE.Group(); hmi.name = 'panel_hmi';
    const shell = plate(0.56, 0.38, 0.042, 0.016, P.carcasa, 'hmi_carcasa');
    const bezel = plate(0.53, 0.35, 0.01, 0.012, P.oscuro, 'hmi_bisel');
    bezel.position.z = 0.024;
    const screen = plate(0.44, 0.285, 0.004, 0.005, P.pantalla, 'hmi_pantalla');
    screen.position.z = 0.029;
    const ui = uiScada(P, 0.43, 0.275, 'hmi_interfaz');
    ui.position.z = 0.0325;
    const strip = plate(0.10, 0.014, 0.004, 0.002, P.claro, 'hmi_marca');
    strip.position.set(-0.20, -0.162, 0.024);
    hmi.add(shell, bezel, screen, ui, strip);
    for (let i = 0; i < 5; i++) {
      const k = plate(0.026, 0.026, 0.008, 0.004, P.oscuro, `hmi_tecla_lateral_${i + 1}`);
      k.position.set(0.245, 0.13 - i * 0.06, 0.024);
      hmi.add(k);
    }
    hmi.position.set(0, Y0 + 0.35, -0.02);
    hmi.rotation.x = -0.08;

    const arm = cyl(0.026, 0.055, P.claro, 'soporte_brazo', 20);
    arm.rotation.x = Math.PI / 2; arm.position.set(0, Y0 + 0.33, -0.075);
    const col = cyl(0.03, 0.22, P.claro, 'soporte_columna', 24, 0.036);
    col.position.set(0, Y0 + 0.13, -0.09);
    const knuckle = cyl(0.036, 0.04, P.oscuro, 'soporte_rotula', 20);
    knuckle.rotation.z = Math.PI / 2; knuckle.position.set(0, Y0 + 0.245, -0.09);
    const foot = plateFlat(0.30, 0.20, 0.016, 0.02, P.carcasa, 'soporte_base');
    foot.position.set(0, Y0 + 0.008, -0.07);
    g.add(hmi, arm, knuckle, col, foot);
    return g;
  }

export function build(accent) {
  const P = palette(accent);
  const g = new THREE.Group();
  g.name = 'nodo_fuxa';
  g.add(plinth(P), contenido(P), glassShell(P), neonFrame(P));
  return g;
}
