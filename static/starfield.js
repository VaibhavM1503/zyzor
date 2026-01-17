const canvas = document.getElementById("miCanvas");
const ctx = canvas.getContext("2d");

function resizeCanvas() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}
resizeCanvas();

let centerX = canvas.width / 2;
let centerY = canvas.height / 2;

/* ======================================================
   ESTRELLAS
====================================================== */
const stars = [];
const STAR_COUNT = 700;

function initStars() {
  stars.length = 0;
  for (let i = 0; i < STAR_COUNT; i++) {
    stars.push({
      x: Math.random() * canvas.width - centerX,
      y: Math.random() * canvas.height - centerY,
      z: Math.random() * canvas.width,
      r: Math.random() * 1.5 + 0.5
    });
  }
}
initStars();

/* ======================================================
   PARTICULAS RAPIDAS
====================================================== */
const particles = [];

function createParticle() {
  const angle = Math.random() * Math.PI * 2;
  const speed = 6 + Math.random() * 6;

  particles.push({
    x: centerX,
    y: centerY,
    vx: Math.cos(angle) * speed,
    vy: Math.sin(angle) * speed,
    life: 0,
    maxLife: 140 + Math.random() * 80,
    collided: false
  });
}

/* ======================================================
   EXPLOSIONES
====================================================== */
const explosions = [];

function createExplosion(x, y, baseVx, baseVy) {
  const count = 12 + Math.floor(Math.random() * 10);

  for (let i = 0; i < count; i++) {
    const angle =
      Math.atan2(baseVy, baseVx) +
      (Math.random() - 0.5) * Math.PI;

    const speed = 2 + Math.random() * 4;

    explosions.push({
      x,
      y,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      life: 0,
      maxLife: 40 + Math.random() * 30
    });
  }

  // Flash breve
  ctx.save();
  ctx.fillStyle = "rgba(255,255,255,0.25)";
  ctx.beginPath();
  ctx.arc(x, y, 8, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}

/* ======================================================
   NEBULOSAS
====================================================== */
const nebulas = [];

function createNebula() {
  const colors = [
    "rgba(120,80,255,",
    "rgba(255,100,180,",
    "rgba(80,200,255,",
    "rgba(150,255,200,"
  ];

  nebulas.push({
    x: Math.random() * canvas.width,
    y: Math.random() * canvas.height,
    radius: 300 + Math.random() * 500,
    color: colors[Math.floor(Math.random() * colors.length)],
    alpha: 0,
    maxAlpha: 0.12 + Math.random() * 0.12,
    phase: "in"
  });
}

/* ======================================================
   LOOP
====================================================== */
function draw() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  /* Fondo estelar */
  ctx.fillStyle = "white";
  for (const s of stars) {
    const x = centerX + (s.x / s.z) * canvas.width;
    const y = centerY + (s.y / s.z) * canvas.height;
    const size = s.r * (1 - s.z / canvas.width);

    ctx.beginPath();
    ctx.arc(x, y, size, 0, Math.PI * 2);
    ctx.fill();

    s.z -= 2;
    if (s.z <= 0) {
      s.z = canvas.width;
      s.x = Math.random() * canvas.width - centerX;
      s.y = Math.random() * canvas.height - centerY;
    }
  }

  /* Partículas */
  if (Math.random() < 0.005) createParticle();

  for (let i = particles.length - 1; i >= 0; i--) {
    const p = particles[i];
    const fade = 1 - p.life / p.maxLife;

    ctx.strokeStyle = `rgba(255,255,255,${fade})`;
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.moveTo(p.x, p.y);
    ctx.lineTo(p.x - p.vx * 2, p.y - p.vy * 2);
    ctx.stroke();

    // Colisión rara con estrellas visibles
    if (!p.collided && Math.random() < 0.002) {
      p.collided = true;
      createExplosion(p.x, p.y, p.vx, p.vy);
    }

    p.x += p.vx;
    p.y += p.vy;
    p.life++;

    if (p.life > p.maxLife) particles.splice(i, 1);
  }

  /* Explosiones */
  for (let i = explosions.length - 1; i >= 0; i--) {
    const e = explosions[i];
    const fade = 1 - e.life / e.maxLife;

    ctx.fillStyle = `rgba(255,255,255,${fade})`;
    ctx.beginPath();
    ctx.arc(e.x, e.y, 1.2, 0, Math.PI * 2);
    ctx.fill();

    e.x += e.vx;
    e.y += e.vy;
    e.life++;

    if (e.life > e.maxLife) explosions.splice(i, 1);
  }

  /* Nebulosas */
  if (Math.random() < 0.002 && nebulas.length < 2) createNebula();

  for (let i = nebulas.length - 1; i >= 0; i--) {
    const n = nebulas[i];

    n.alpha += n.phase === "in" ? 0.0015 : -0.001;
    if (n.alpha >= n.maxAlpha) n.phase = "out";
    if (n.alpha <= 0) {
      nebulas.splice(i, 1);
      continue;
    }

    const gradient = ctx.createRadialGradient(
      n.x, n.y, 0, n.x, n.y, n.radius
    );

    gradient.addColorStop(0, `${n.color}${n.alpha})`);
    gradient.addColorStop(1, `${n.color}0)`);

    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
  }

  requestAnimationFrame(draw);
}

draw();

window.addEventListener("resize", () => {
  resizeCanvas();
  centerX = canvas.width / 2;
  centerY = canvas.height / 2;
  initStars();
});

