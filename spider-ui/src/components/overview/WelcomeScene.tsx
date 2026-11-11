import { useEffect, useRef } from 'react';
import * as THREE from 'three';

export interface WelcomeSceneProps {
  paused?: boolean;
}

export function WelcomeScene({ paused = false }: WelcomeSceneProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Check WebGL availability
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        alpha: true,
        powerPreference: 'low-power',
      });
    } catch {
      return; // WebGL unavailable: parent fallback will remain
    }

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    renderer.setPixelRatio(dpr);
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(
      45,
      container.clientWidth / container.clientHeight,
      0.1,
      100
    );
    camera.position.set(0, 0, 7);

    // 1. Procedural web strands
    const strandCount = 18;
    const strandGeometries: THREE.BufferGeometry[] = [];
    const strandMaterials: THREE.LineBasicMaterial[] = [];
    const strandGroup = new THREE.Group();

    for (let i = 0; i < strandCount; i++) {
      const points: THREE.Vector3[] = [];
      const angle = (i / strandCount) * Math.PI * 2;
      const radius = 2.5 + Math.sin(i * 1.5) * 0.8;
      const p1 = new THREE.Vector3(0, 0, 0);
      const p2 = new THREE.Vector3(
        Math.cos(angle) * radius,
        Math.sin(angle) * radius * 0.8,
        (Math.random() - 0.5) * 0.5
      );
      points.push(p1, p2);

      const geom = new THREE.BufferGeometry().setFromPoints(points);
      const mat = new THREE.LineBasicMaterial({
        color: 0x2aa78a,
        transparent: true,
        opacity: 0.25,
      });
      const line = new THREE.Line(geom, mat);
      strandGeometries.push(geom);
      strandMaterials.push(mat);
      strandGroup.add(line);
    }
    scene.add(strandGroup);

    // 2. Drifting particles
    const particleCount = 60;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i += 3) {
      particlePositions[i] = (Math.random() - 0.5) * 7;
      particlePositions[i + 1] = (Math.random() - 0.5) * 6;
      particlePositions[i + 2] = (Math.random() - 0.5) * 2;
    }
    const particleGeom = new THREE.BufferGeometry();
    particleGeom.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({
      color: 0x83ebd1,
      size: 0.05,
      transparent: true,
      opacity: 0.45,
    });
    const particleSystem = new THREE.Points(particleGeom, particleMat);
    scene.add(particleSystem);

    // 3. Central idle spider silhouette aligned with ExperienceArtwork spider
    const spiderGroup = new THREE.Group();
    spiderGroup.position.set(0, 0.45, 0);

    // Cephalothorax & abdomen
    const headGeom = new THREE.SphereGeometry(0.14, 12, 12);
    headGeom.scale(1, 0.75, 0.7);
    const bodyGeom = new THREE.SphereGeometry(0.24, 14, 14);
    bodyGeom.scale(1, 1.15, 0.8);

    const spiderMat = new THREE.MeshBasicMaterial({
      color: 0x061713,
      wireframe: false,
    });
    const spiderEdgeMat = new THREE.LineBasicMaterial({
      color: 0x62e6c5,
      transparent: true,
      opacity: 0.85,
    });

    const headMesh = new THREE.Mesh(headGeom, spiderMat);
    headMesh.position.set(0, 0.18, 0);
    const bodyMesh = new THREE.Mesh(bodyGeom, spiderMat);
    bodyMesh.position.set(0, -0.16, 0);

    const headEdges = new THREE.LineSegments(new THREE.EdgesGeometry(headGeom), spiderEdgeMat);
    headEdges.position.copy(headMesh.position);
    const bodyEdges = new THREE.LineSegments(new THREE.EdgesGeometry(bodyGeom), spiderEdgeMat);
    bodyEdges.position.copy(bodyMesh.position);

    spiderGroup.add(headMesh, bodyMesh, headEdges, bodyEdges);

    // Spider legs (8 legs) matching isometric artwork spread
    const legGeometries: THREE.BufferGeometry[] = [];
    for (let i = 0; i < 8; i++) {
      const side = i < 4 ? 1 : -1;
      const index = i % 4;
      const legPoints = [
        new THREE.Vector3(side * 0.1, 0.08 - index * 0.07, 0),
        new THREE.Vector3(side * (0.42 + index * 0.08), 0.2 - index * 0.1, 0.15),
        new THREE.Vector3(side * (0.68 + index * 0.1), -0.14 - index * 0.14, 0),
      ];
      const legGeom = new THREE.BufferGeometry().setFromPoints(legPoints);
      const legLine = new THREE.Line(legGeom, spiderEdgeMat);
      legGeometries.push(legGeom);
      spiderGroup.add(legLine);
    }

    scene.add(spiderGroup);

    // Mouse interaction & parallax
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
      targetX = x;
      targetY = y;
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Visibility observer to pause when hidden
    let isTabVisible = !document.hidden;
    const handleVisibility = () => {
      isTabVisible = !document.hidden;
    };
    document.addEventListener('visibilitychange', handleVisibility);

    // Resize listener
    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    // Animation Loop
    let animId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);

      if (pausedRef.current || !isTabVisible) return;

      const delta = clock.getDelta();
      const time = clock.getElapsedTime();

      // Smooth mouse interpolation
      mouseX += (targetX - mouseX) * 0.05;
      mouseY += (targetY - mouseY) * 0.05;

      // Parallax on camera & spider
      camera.position.x = mouseX * 0.6;
      camera.position.y = mouseY * 0.4;
      camera.lookAt(0, 0, 0);

      // Spider subtle idle breath
      spiderGroup.position.y = 0.45 + Math.sin(time * 1.5) * 0.05;
      spiderGroup.rotation.z = Math.sin(time * 0.8) * 0.03 + mouseX * 0.05;

      // Web strands brightness near cursor
      const cursorDist = Math.sqrt(mouseX * mouseX + mouseY * mouseY);
      strandMaterials.forEach((mat) => {
        mat.opacity = 0.2 + (1 - Math.min(cursorDist, 1)) * 0.35;
      });

      // Drifting particles rotation
      particleSystem.rotation.y = time * 0.03;
      particleSystem.rotation.x = Math.sin(time * 0.02) * 0.05;

      renderer.render(scene, camera);
    };

    animate();

    // Clean up
    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      document.removeEventListener('visibilitychange', handleVisibility);

      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }

      // Dispose geometries & materials
      strandGeometries.forEach((g) => g.dispose());
      strandMaterials.forEach((m) => m.dispose());
      particleGeom.dispose();
      particleMat.dispose();
      headGeom.dispose();
      bodyGeom.dispose();
      spiderMat.dispose();
      spiderEdgeMat.dispose();
      headEdges.geometry.dispose();
      bodyEdges.geometry.dispose();
      legGeometries.forEach((g) => g.dispose());
      renderer.dispose();
    };
  }, []);

  return (
    <div
      ref={containerRef}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 1,
      }}
      aria-hidden="true"
    />
  );
}

export default WelcomeScene;

