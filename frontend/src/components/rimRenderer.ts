/** Project the cached hero text onto a narrow elliptical rim in one draw call. */
export function createRimRenderer(canvas: HTMLCanvasElement) {
  const gl = canvas.getContext("webgl", {
    alpha: true, depth: false, stencil: false, antialias: true, powerPreference: "low-power",
  });
  if (!gl) return null;

  const program = gl.createProgram();
  const buffer = gl.createBuffer();
  const texture = gl.createTexture();
  const dispose = () => {
    gl.deleteTexture(texture);
    gl.deleteBuffer(buffer);
    gl.deleteProgram(program);
  };
  if (!program || !buffer || !texture) { dispose(); return null; }
  const vertex = `
    attribute vec3 rim;
    uniform vec2 atlasSize;
    uniform vec2 lensSize;
    uniform float centerY;
    varying vec2 uv;
    void main() {
      vec2 n = rim.xy;
      vec2 normal = normalize(n / lensSize);
      vec2 center = vec2(atlasSize.x * .5, centerY);
      vec2 samplePoint = center + n * lensSize * .454 - normal * rim.z * lensSize.y * .0675;
      uv = samplePoint / atlasSize;
      gl_Position = vec4(n * vec2(1., -1.) * (.908 + rim.z * .045), 0., 1.);
    }`;
  const fragment = `
    precision mediump float;
    uniform sampler2D glyphs;
    varying vec2 uv;
    void main() {
      if (any(lessThan(uv, vec2(0.))) || any(greaterThan(uv, vec2(1.)))) discard;
      gl_FragColor = texture2D(glyphs, uv);
    }`;
  for (const [type, source] of [[gl.VERTEX_SHADER, vertex], [gl.FRAGMENT_SHADER, fragment]] as const) {
    const shader = gl.createShader(type);
    if (!shader) { dispose(); return null; }
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    gl.attachShader(program, shader);
    gl.deleteShader(shader);
  }
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) { dispose(); return null; }
  gl.useProgram(program);
  const vertices: number[] = [];
  for (let i = 0; i <= 128; i++) {
    const angle = i * Math.PI / 64;
    const x = Math.sin(angle), y = -Math.cos(angle);
    vertices.push(x, y, -1, x, y, 1);
  }
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(vertices), gl.STATIC_DRAW);
  const rim = gl.getAttribLocation(program, "rim");
  gl.enableVertexAttribArray(rim);
  gl.vertexAttribPointer(rim, 3, gl.FLOAT, false, 0, 0);
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, true);
  const atlasSize = gl.getUniformLocation(program, "atlasSize");
  const lensSize = gl.getUniformLocation(program, "lensSize");
  const centerY = gl.getUniformLocation(program, "centerY");
  const maxSize = gl.getParameter(gl.MAX_TEXTURE_SIZE) as number;
  let ready = false;
  return {
    upload(atlas: HTMLCanvasElement) {
      ready = !!atlas.width && !!atlas.height && Math.max(atlas.width, atlas.height) <= maxSize && !gl.isContextLost();
      if (!ready) return;
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, atlas);
      gl.uniform2f(atlasSize, atlas.width, atlas.height);
    },
    draw(y: number, width: number, height: number) {
      if (!ready || gl.isContextLost()) return false;
      gl.uniform2f(lensSize, width, height);
      gl.uniform1f(centerY, y);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, vertices.length / 3);
      return true;
    },
    dispose,
  };
}
