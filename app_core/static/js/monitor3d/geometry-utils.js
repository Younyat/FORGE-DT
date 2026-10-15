import * as THREE from "three";

// Concatenates same-format indexed BufferGeometries (position/normal/uv --
// what every standard THREE geometry factory already produces) into one.
// Deliberately hand-rolled instead of vendoring three/addons'
// BufferGeometryUtils for two small call sites -- merge is the only
// operation needed, and every input geometry involved is already this
// exact shape. Shared by host-visuals.js (batching a detailed node
// model's many meshes into one draw call per material) and entities.js
// (fusing a relation-line tube with its arrowhead cone into one mesh).
export function mergeIndexedGeometries(geometries) {
  const positions = [], normals = [], uvs = [], indices = [];
  let vertexOffset = 0;
  for (const g of geometries) {
    const pos = g.getAttribute("position");
    const norm = g.getAttribute("normal");
    const uv = g.getAttribute("uv");
    for (let i = 0; i < pos.count; i++) {
      positions.push(pos.getX(i), pos.getY(i), pos.getZ(i));
      if (norm) normals.push(norm.getX(i), norm.getY(i), norm.getZ(i));
      if (uv) uvs.push(uv.getX(i), uv.getY(i));
    }
    if (g.index) {
      for (let i = 0; i < g.index.count; i++) indices.push(g.index.getX(i) + vertexOffset);
    } else {
      for (let i = 0; i < pos.count; i++) indices.push(i + vertexOffset);
    }
    vertexOffset += pos.count;
  }
  const merged = new THREE.BufferGeometry();
  merged.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
  if (normals.length) merged.setAttribute("normal", new THREE.Float32BufferAttribute(normals, 3));
  if (uvs.length) merged.setAttribute("uv", new THREE.Float32BufferAttribute(uvs, 2));
  merged.setIndex(indices);
  return merged;
}

// A detailed procedural node model (host or case) is ~140 individually-
// drawn meshes (a keyboard alone is 50+ separate key meshes) -- measured
// this session to collapse frame rate from ~54fps (plain boxes) to
// ~4-9fps once several such models share a scene, even after removing
// glass transmission. Draw-call count, not triangle count, is the
// dominant cost (a full 5-host scene's ~130k-317k triangles is trivial
// for any real GPU on its own). Since every mesh sharing a material is
// already meant to look identical (they share the SAME material
// *instance* from partes-comunes.js's palette()/mat() helpers, not just
// matching colors), batching every mesh that shares a material into one
// merged Mesh preserves the exact triangle count and visual result while
// cutting draw calls to roughly the model's material count (~10-15).
// Shared by host-visuals.js and case-visuals.js.
export function collapseDrawCalls(root) {
  root.updateMatrixWorld(true);
  const rootInverse = new THREE.Matrix4().copy(root.matrixWorld).invert();
  const byMaterial = new Map();
  root.traverse((o) => {
    if (!o.isMesh) return;
    const list = byMaterial.get(o.material) || [];
    list.push(o);
    byMaterial.set(o.material, list);
  });

  const merged = new THREE.Group();
  merged.name = root.name;
  for (const [material, meshes] of byMaterial) {
    const localMatrix = new THREE.Matrix4();
    const geometries = meshes.map((m) => {
      const geo = m.geometry.clone();
      localMatrix.multiplyMatrices(rootInverse, m.matrixWorld);
      geo.applyMatrix4(localMatrix);
      return geo;
    });
    const mesh = new THREE.Mesh(mergeIndexedGeometries(geometries), material);
    mesh.name = (meshes[0].name || "part") + "_batch";
    merged.add(mesh);
    for (const geo of geometries) geo.dispose();
  }
  return merged;
}

// Flags every geometry/material in a cached, permanently-reused model so
// entities.js's disposeEntity() knows to never dispose them when an
// individual box using this shared model is torn down (rebuilds happen
// roughly every 2-3s from live polling; rebuilding+merging a model from
// scratch every time was the actual cause of a real, measured "orbiting
// feels sluggish" regression -- see host-visuals.js/case-visuals.js).
export function markShared(model) {
  model.traverse((o) => {
    if (o.geometry) o.geometry.userData.sharedNodeVisual = true;
    if (o.material) o.material.userData.sharedNodeVisual = true;
  });
}
