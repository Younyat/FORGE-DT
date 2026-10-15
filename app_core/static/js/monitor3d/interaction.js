import * as THREE from "three";

// Picking: walks from whatever mesh was hit to its parent Group's userData.
// Single click = select, double-click = drill/expand, mousemove = hover.
export function attachInteraction(domElement, camera, pickableGroups, { onSelect, onDrillDown, onHover }) {
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();

  function pick(event) {
    const rect = domElement.getBoundingClientRect();
    pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(pointer, camera);
    // .filter(Boolean): real bug found 2026-10-13 adding persistent relation
    // lines to Live Attack View -- pickableGroups() can legitimately include
    // plain decorative meshes that were never meant to be clickable/hoverable
    // (relation-line connectors, the missile-projectile animation, both
    // pushed into liveObjects purely so exit() can dispose them, same as
    // every other live object). Those have no `userData.mesh`, so without
    // this filter `meshes` gets `undefined` entries and
    // `raycaster.intersectObjects` throws "Cannot read properties of
    // undefined (reading 'layers')" on every mousemove once one is on
    // screen. Previously latent (the missile only exists for ~2s, rarely
    // hovered during that window) -- a persistent relation line made it
    // reproduce on every hover.
    const meshes = pickableGroups().map((g) => g.userData.mesh).filter(Boolean);
    // Recursive: a plain box's userData.mesh is a single leaf Mesh (no
    // children, so this changes nothing for it), but a detailed node-model
    // (host-visuals.js) is a multi-mesh Group -- Object3D.raycast() is a
    // no-op, so without recursion clicking directly on the model would
    // never register a hit at all. Every child mesh of such a model has
    // its userData set to the SAME object as the owning group's userData
    // (createEntityBox's visualModel branch), so hits[0].object.userData
    // still resolves to the right entity either way.
    const hits = raycaster.intersectObjects(meshes, true);
    return hits.length ? hits[0].object.userData : null;
  }

  domElement.addEventListener("click", (event) => {
    const hit = pick(event);
    if (hit) onSelect?.(hit);
  });
  domElement.addEventListener("dblclick", (event) => {
    const hit = pick(event);
    if (hit) onDrillDown?.(hit);
  });
  let lastHoverId = null;
  domElement.addEventListener("mousemove", (event) => {
    const hit = pick(event);
    const id = hit?.id || null;
    if (id !== lastHoverId) {
      lastHoverId = id;
      onHover?.(hit);
    }
  });
}
