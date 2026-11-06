/** Saved scientific samples only: this viewer never advances a simulation. */
import {formatNumber, statusLabel, chartPoints} from './view-model.mjs';
import {readDynamicsPayload, cameraForFrames, projectPoint, selectFrameAtFraction,
  fractionAtFrame, dynamicsSeries, frameParticle} from './dynamics-model.mjs';

const palette = ['#168a78', '#cf7950', '#6879b5', '#b05b8a', '#82954b', '#468aaa', '#b88d38', '#7561a1'];
const axisColors = ['#c7705c', '#458a6b', '#607fb0'];
const graphGroups = {
  energy: {title: '에너지', unit: 'J', keys: ['energyK', 'energyU', 'energyE'], names: ['K', 'U', 'E']},
  momentum: {title: '선운동량', unit: 'kg·m/s', keys: ['Px', 'Py', 'Pz'], names: ['Px', 'Py', 'Pz']},
  angular: {title: '각운동량', unit: 'kg·m²/s', keys: ['Lx', 'Ly', 'Lz'], names: ['Lx', 'Ly', 'Lz']},
};
const exact = value => typeof value === 'number' && Number.isFinite(value)
  ? Object.is(value, -0) ? '-0' : String(value) : '—';
const clamp = (value, low, high) => Math.max(low, Math.min(high, value));

/**
 * Mount into the existing result cards. dispose() must be called before another
 * run/step, logout, or removal. pause() preserves the selected saved frame.
 * Raw selected values are also exposed as data-raw-value (never rounded pixels).
 */
export function mountDynamicsViewer({payload, host, tableHost, metricsHost}) {
  const doc = host.ownerDocument;
  const win = doc.defaultView;
  const ownNodes = [];
  const listeners = [];
  const el = (tag, className = '', text) => {
    const result = doc.createElement(tag);
    if (className) result.className = className;
    if (text !== undefined) result.textContent = String(text);
    return result;
  };
  const own = (parent, child) => { parent.append(child); ownNodes.push(child); return child; };
  const listen = (target, event, callback, options) => {
    target.addEventListener(event, callback, options);
    listeners.push(() => target.removeEventListener(event, callback, options));
  };
  let disposed = false;
  let raf = 0;
  let playing = false;
  let observer = null;
  let model;
  try { model = readDynamicsPayload(payload); }
  catch (error) {
    const failure = own(host, el('div', 'dynamics-error'));
    failure.setAttribute('role', 'alert');
    failure.append(el('h2', '', '궤적을 표시할 수 없습니다.'),
      el('p', '', error?.message || '지원하는 저장 궤적의 형식과 범위를 확인하세요.'),
      el('p', 'chart-caption', '원본 결과와 산출물 다운로드는 아래에서 계속 이용할 수 있습니다.'));
    return {pause() {}, dispose() { ownNodes.forEach(item => item.remove()); }};
  }

  const root = own(host, el('section', 'dynamics-viewer'));
  root.setAttribute('aria-label', '저장된 입자 동역학 궤적');
  const top = el('div', 'dynamics-heading');
  const title = el('div');
  title.append(el('span', 'eyebrow', 'SAVED PARTICLE TRAJECTORY'), el('h2', '', '시간에 따른 입자 배치'));
  const legLabel = el('label', 'dynamics-select-label', '시간간격 비교');
  const legSelect = el('select');
  legSelect.id = 'dynamics-leg';
  for (const [index, leg] of model.legs.entries()) {
    const option = el('option', '', leg.refinement_factor === 1 ? '기본 h · 원본 궤적' : '비교 h/' + leg.refinement_factor);
    option.value = String(index);
    legSelect.append(option);
  }
  legLabel.append(legSelect);
  top.append(title, legLabel);
  root.append(top);

  const warning = el('p', 'dynamics-warning');
  warning.id = 'dynamics-partial';
  warning.setAttribute('role', 'status');
  root.append(warning);
  const scene = el('div', 'dynamics-scene');
  const canvas = el('canvas', 'dynamics-canvas');
  canvas.id = 'dynamics-canvas';
  canvas.width = 800;
  canvas.height = 420;
  canvas.tabIndex = 0;
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', '저장한 입자 위치의 3차원 직교 투영. 방향키로 회전, Shift와 방향키로 이동, 더하기와 빼기로 확대, Home으로 전체 보기.');
  canvas.setAttribute('aria-describedby', 'dynamics-camera-help');
  const sceneStatus = el('div', 'dynamics-scene-label', '3D · 직교 투영 · SI');
  const fallback = el('p', 'dynamics-canvas-fallback', '이 환경에서는 입자 화면을 그릴 수 없습니다. 아래의 원본 수치와 다운로드를 이용하세요.');
  fallback.hidden = true;
  scene.append(canvas, sceneStatus, fallback);
  root.append(scene);

  const cameraTools = el('div', 'dynamics-camera-tools');
  const button = (text, label, className = 'button secondary small') => {
    const result = el('button', className, text);
    result.type = 'button';
    if (label) result.setAttribute('aria-label', label);
    return result;
  };
  const orbitButton = button('회전', '드래그로 회전');
  const panButton = button('이동', '드래그로 화면 이동');
  orbitButton.setAttribute('aria-pressed', 'true');
  panButton.setAttribute('aria-pressed', 'false');
  const zoomOut = button('−', '입자 화면 축소');
  const zoomIn = button('+', '입자 화면 확대');
  const reset = button('전체 보기', '기본 카메라와 전체 궤적으로 돌아가기');
  reset.id = 'dynamics-fit';
  const pathLabel = el('label', 'dynamics-check');
  const pathToggle = el('input');
  pathToggle.type = 'checkbox'; pathToggle.checked = true;
  pathLabel.append(pathToggle, el('span', '', '선택 입자 저장궤적'));
  cameraTools.append(orbitButton, panButton, zoomOut, zoomIn, reset, pathLabel);
  root.append(cameraTools);
  const help = el('p', 'chart-caption', '드래그로 회전 · 이동 버튼 또는 Shift+드래그로 이동 · 스크롤/두 손가락으로 확대 · 입자를 누르면 선택합니다. 점의 크기와 색은 구분용입니다.');
  help.id = 'dynamics-camera-help';
  root.append(help);

  const controls = el('div', 'dynamics-playback');
  const playbackButtons = el('div', 'dynamics-playback-buttons');
  const first = button('처음', '첫 저장 프레임'); first.id = 'dynamics-first';
  const previous = button('이전', '이전 저장 프레임'); previous.id = 'dynamics-previous';
  const play = button('재생', '저장 궤적 재생', 'button primary small'); play.id = 'dynamics-play';
  const next = button('다음', '다음 저장 프레임'); next.id = 'dynamics-next';
  const last = button('끝', '마지막 저장 프레임'); last.id = 'dynamics-last';
  playbackButtons.append(first, previous, play, next, last);
  const speedLabel = el('label', 'dynamics-select-label', '화면 재생 속도');
  const speed = el('select'); speed.id = 'dynamics-speed';
  for (const value of [.5, 1, 2]) {
    const option = el('option', '', value + '배'); option.value = String(value); option.selected = value === 1; speed.append(option);
  }
  speedLabel.append(speed);
  controls.append(playbackButtons, speedLabel);
  root.append(controls);
  const rangeLabel = el('label', 'dynamics-timeline-label', '저장 프레임');
  const range = el('input', 'dynamics-timeline');
  range.type = 'range'; range.id = 'dynamics-frame'; range.min = '0'; range.step = '1';
  rangeLabel.append(range);
  const frameInfo = el('div', 'dynamics-frame-info');
  const timeText = el('strong'); timeText.id = 'dynamics-time';
  const frameText = el('span'); frameText.id = 'dynamics-frame-label';
  frameInfo.append(timeText, frameText);
  root.append(rangeLabel, frameInfo);
  const playbackNote = el('p', 'chart-caption'); playbackNote.id = 'dynamics-playback-note';
  const cameraNote = el('p', 'chart-caption dynamics-camera-note');
  root.append(playbackNote, cameraNote);

  const graphHeader = el('div', 'dynamics-graph-heading');
  graphHeader.append(el('h3', '', '같은 시각의 관측량'));
  const graphLabel = el('label', 'dynamics-select-label', '표시할 관측량');
  const graphSelect = el('select'); graphSelect.id = 'dynamics-observable';
  for (const [key, group] of Object.entries(graphGroups)) { const option = el('option', '', group.title); option.value = key; graphSelect.append(option); }
  graphLabel.append(graphSelect); graphHeader.append(graphLabel);
  const graph = el('div', 'dynamics-graph'); graph.id = 'dynamics-graph';
  root.append(graphHeader, graph, el('p', 'chart-caption', '선은 저장 표본만 연결합니다. 세로 커서·입자 배치·아래 수치는 같은 저장 프레임을 가리킵니다. 표본 사이의 계산 상태를 만들지 않습니다.'));

  const details = own(tableHost, el('section', 'dynamics-data'));
  const detailHeading = el('div', 'dynamics-heading'); detailHeading.append(el('h2', '', '선택 입자의 원본 수치'));
  const particleLabel = el('label', 'dynamics-select-label', '입자 ID');
  const particleSelect = el('select'); particleSelect.id = 'dynamics-particle';
  for (const [index, id] of model.ids.entries()) { const option = el('option', '', id); option.value = String(index); particleSelect.append(option); }
  particleLabel.append(particleSelect); detailHeading.append(particleLabel);
  const selectedValues = el('dl', 'dynamics-values'); selectedValues.id = 'dynamics-selected-values';
  const fields = new Map();
  for (const [key, label] of [['mass_kg', '질량 (kg)'], ['x_m', 'x (m)'], ['y_m', 'y (m)'], ['z_m', 'z (m)'],
    ['vx_m_per_s', 'vx (m/s)'], ['vy_m_per_s', 'vy (m/s)'], ['vz_m_per_s', 'vz (m/s)'], ['fx_n', 'Fx (N)'], ['fy_n', 'Fy (N)'], ['fz_n', 'Fz (N)']]) {
    const row = el('div'); const value = el('dd'); value.dataset.field = key;
    row.append(el('dt', '', label), value); selectedValues.append(row); fields.set(key, value);
  }
  details.append(detailHeading, selectedValues, el('p', 'chart-caption', 'SI binary64 원본 수치를 표시합니다. 카메라의 원점·척도 변환은 표시용이며 저장값을 바꾸지 않습니다.'));
  const diagnosticHeading = el('h3', 'dynamics-diagnostic-heading', '모든 수락 스텝의 누적 진단');
  const diagnosticValues = el('dl', 'dynamics-diagnostics'); diagnosticValues.id = 'dynamics-diagnostics';
  details.append(diagnosticHeading, diagnosticValues, el('p', 'chart-caption', '누적 최대값은 저장된 그래프 점만의 최대값이 아닙니다. 수치 기준·시간간격 비교와 실제 현상에 대한 물리 검증은 구분하며 물리 검증은 unvalidated입니다.'));

  const metrics = [];
  for (const [label, unit] of [['선택한 물리 시각', 's'], ['저장 프레임', '개'], ['선택한 총에너지', 'J']]) {
    const card = own(metricsHost, el('div', 'metric-card'));
    const value = el('span', 'metric-value');
    const valueText = doc.createTextNode('—');
    value.append(valueText, el('span', 'metric-unit', unit)); card.append(el('span', 'metric-label', label), value); metrics.push(valueText);
  }

  let legIndex = model.legs.findIndex(leg => leg.refinement_factor === 1);
  let frameIndex = 0;
  let particleIndex = 0;
  let camera = null;
  let yaw = -.55;
  let pitch = .35;
  let zoom = 1;
  let panX = 0;
  let panY = 0;
  let dragMode = 'orbit';
  let screenWidth = 800;
  let screenHeight = 420;
  let screenPoints = [];
  let graphView = null;
  let startedAt = null;
  let startedFraction = 0;
  const pointers = new Map();
  let moved = false;
  let context = null;
  try { context = canvas.getContext('2d'); } catch { /* numeric fallback remains available */ }
  fallback.hidden = !!context;
  canvas.hidden = !context;
  for (const control of [orbitButton, panButton, zoomOut, zoomIn, reset, pathToggle]) control.disabled = !context;
  const leg = () => model.legs[legIndex];
  const frames = () => leg().sampled_frames;
  const active = () => !disposed && root.isConnected && !doc.hidden && !root.closest('[hidden]');
  function pause() {
    playing = false;
    if (raf) win.cancelAnimationFrame(raf);
    raf = 0; startedAt = null;
    play.textContent = '재생'; play.setAttribute('aria-label', '저장 궤적 재생'); play.setAttribute('aria-pressed', 'false');
  }
  function resetCamera() { yaw = -.55; pitch = .35; zoom = 1; panX = 0; panY = 0; drawScene(); }
  function setZoom(value) { zoom = clamp(value, .15, 40); drawScene(); }
  function cameraView() { return {width: screenWidth, height: screenHeight, yaw, pitch, zoom, panX, panY}; }
  function resize() {
    if (disposed || !context) return;
    const rect = scene.getBoundingClientRect();
    if (rect.width < 1) return;
    screenWidth = rect.width;
    screenHeight = Math.max(250, Math.min(460, rect.width * .58));
    const ratio = Math.min(win.devicePixelRatio || 1, 2);
    canvas.width = Math.round(screenWidth * ratio); canvas.height = Math.round(screenHeight * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    drawScene();
  }
  function drawScene() {
    if (!context || disposed || !camera) return;
    const ctx = context;
    ctx.clearRect(0, 0, screenWidth, screenHeight);
    ctx.fillStyle = '#f7faf7'; ctx.fillRect(0, 0, screenWidth, screenHeight);
    const frame = frames()[frameIndex];
    const view = cameraView();
    const project = point => projectPoint(point, camera, view);
    if (pathToggle.checked) {
      ctx.beginPath();
      for (const [index, sample] of frames().entries()) {
        const p = project(sample.positions_m[particleIndex]);
        if (index === 0) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
      }
      ctx.strokeStyle = palette[particleIndex % palette.length] + '88'; ctx.lineWidth = 1.5; ctx.stroke();
      for (const sample of frames()) { const p = project(sample.positions_m[particleIndex]); ctx.beginPath(); ctx.arc(p.x, p.y, 1.6, 0, 2 * Math.PI); ctx.fillStyle = '#6f988d'; ctx.fill(); }
    }
    screenPoints = frame.positions_m.map((point, index) => ({...project(point), index})).sort((a, b) => a.depth - b.depth);
    for (const point of screenPoints) {
      const selected = point.index === particleIndex;
      ctx.beginPath(); ctx.arc(point.x, point.y, selected ? 7 : 5, 0, 2 * Math.PI);
      ctx.fillStyle = palette[point.index % palette.length]; ctx.fill();
      ctx.lineWidth = selected ? 2 : 1; ctx.strokeStyle = '#ffffff'; ctx.stroke();
      if (selected) { ctx.beginPath(); ctx.arc(point.x, point.y, 11, 0, 2 * Math.PI); ctx.strokeStyle = '#294f43'; ctx.lineWidth = 1.4; ctx.stroke(); }
      if (model.ids.length <= 16 || selected) {
        ctx.font = '11px ui-monospace, monospace'; ctx.fillStyle = '#315e50'; ctx.fillText(model.ids[point.index], point.x + 13, point.y - 10);
      }
    }
    const widgetCamera = {origin: [0, 0, 0], scale_m: 1, radius: 1, degenerate: false};
    const widgetView = {width: 80, height: 80, yaw, pitch, zoom: .7, panX: 0, panY: 0};
    const origin = projectPoint([0, 0, 0], widgetCamera, widgetView);
    for (const [index, vector] of [[1, 0, 0], [0, 1, 0], [0, 0, 1]].entries()) {
      const tip = projectPoint(vector, widgetCamera, widgetView);
      const ox = 12, oy = screenHeight - 90;
      ctx.beginPath(); ctx.moveTo(origin.x + ox, origin.y + oy); ctx.lineTo(tip.x + ox, tip.y + oy); ctx.strokeStyle = axisColors[index]; ctx.lineWidth = 1.8; ctx.stroke();
      ctx.font = '11px ui-monospace, monospace'; ctx.fillStyle = axisColors[index]; ctx.fillText('xyz'[index], tip.x + ox + 3, tip.y + oy - 3);
    }
    ctx.font = '10px ui-monospace, monospace'; ctx.fillStyle = '#7e978c'; ctx.fillText('axes · m', 20, screenHeight - 10);
  }

  function svgNode(name, attributes = {}, text) {
    const result = doc.createElementNS('http://www.w3.org/2000/svg', name);
    for (const [key, value] of Object.entries(attributes)) result.setAttribute(key, String(value));
    if (text !== undefined) result.textContent = String(text);
    return result;
  }
  function buildGraph() {
    graph.replaceChildren();
    const group = graphGroups[graphSelect.value];
    const series = group.keys.map(key => dynamicsSeries(leg(), key));
    const count = frames().length;
    const xs = series.flatMap(item => item.xs);
    const ys = series.flatMap(item => item.ys);
    const geometry = chartPoints(xs, ys, 700, 260, 48);
    const svg = svgNode('svg', {viewBox: '0 0 700 260', class: 'dynamics-chart-svg', role: 'img', 'aria-label': group.title + ' 저장 표본 · 물리 시각(s) / ' + group.unit});
    for (let i = 0; i <= 4; i++) {
      const ratio = i / 4; const y = geometry.top + ratio * (geometry.bottom - geometry.top);
      svg.append(svgNode('line', {x1: geometry.left, x2: geometry.right, y1: y, y2: y, class: 'dynamics-chart-grid'}));
      const value = geometry.yMax * (1 - ratio) + geometry.yMin * ratio;
      svg.append(svgNode('text', {x: geometry.left - 8, y: y + 3, 'text-anchor': 'end', class: 'dynamics-chart-label'}, formatNumber(value, 3)));
    }
    for (const ratio of [0, .5, 1]) {
      const x = geometry.left + ratio * (geometry.right - geometry.left);
      const value = geometry.xMin * (1 - ratio) + geometry.xMax * ratio;
      svg.append(svgNode('text', {x, y: geometry.bottom + 20, 'text-anchor': 'middle', class: 'dynamics-chart-label'}, formatNumber(value, 3)));
    }
    svg.append(svgNode('text', {x: geometry.left, y: 17, class: 'dynamics-chart-label'}, group.unit),
      svgNode('text', {x: 350, y: 255, 'text-anchor': 'middle', class: 'dynamics-chart-label'}, '물리 시각 (s)'));
    const samples = [];
    for (let index = 0; index < series.length; index++) {
      const points = geometry.samples.slice(index * count, (index + 1) * count);
      samples.push(points);
      svg.append(svgNode('polyline', {points: points.map(p => `${p.px},${p.py}`).join(' '), class: 'dynamics-chart-line dynamics-series-' + index}));
    }
    const cursor = svgNode('line', {y1: geometry.top, y2: geometry.bottom, class: 'dynamics-chart-cursor'});
    svg.append(cursor);
    const markers = samples.map((_, i) => { const marker = svgNode('circle', {r: 4, class: 'dynamics-chart-point dynamics-series-' + i}); svg.append(marker); return marker; });
    const legend = el('div', 'dynamics-legend');
    const values = series.map((_, index) => { const item = el('span', 'dynamics-legend-item dynamics-color-' + index); item.append(el('strong', '', group.names[index] + ' ')); const value = el('span'); value.dataset.series = group.keys[index]; item.append(value); legend.append(item); return value; });
    graph.append(legend, svg);
    graphView = {series, samples, cursor, markers, values};
  }
  function updateGraph() {
    if (!graphView) return;
    const p = graphView.samples[0][frameIndex];
    graphView.cursor.setAttribute('x1', String(p.px)); graphView.cursor.setAttribute('x2', String(p.px));
    graphView.cursor.dataset.timeS = exact(frames()[frameIndex].time_s);
    graphView.series.forEach((series, i) => {
      const point = graphView.samples[i][frameIndex];
      graphView.markers[i].setAttribute('cx', String(point.px)); graphView.markers[i].setAttribute('cy', String(point.py));
      graphView.values[i].textContent = formatNumber(series.ys[frameIndex], 10);
      graphView.values[i].dataset.rawValue = exact(series.ys[frameIndex]);
    });
  }
  function selectFrame(index) {
    frameIndex = clamp(index, 0, frames().length - 1);
    const frame = frames()[frameIndex];
    const selected = frameParticle(model, legIndex, frameIndex, particleIndex);
    root.dataset.frameIndex = String(frameIndex); root.dataset.timeS = exact(frame.time_s);
    root.dataset.stepIndex = String(frame.step_index); root.dataset.particleId = selected.id; root.dataset.refinementFactor = String(leg().refinement_factor);
    range.value = String(frameIndex); range.setAttribute('aria-valuetext', '프레임 ' + (frameIndex + 1) + ', 물리 시각 ' + exact(frame.time_s) + '초, 계산 스텝 ' + frame.step_index);
    timeText.textContent = 't = ' + exact(frame.time_s) + ' s';
    frameText.textContent = (frameIndex + 1) + ' / ' + frames().length + ' 프레임 · 스텝 ' + frame.step_index;
    const values = [selected.mass_kg, ...selected.position_m, ...selected.velocity_m_per_s, ...selected.force_n];
    [...fields.values()].forEach((target, index) => { target.textContent = exact(values[index]); target.dataset.rawValue = exact(values[index]); });
    metrics[0].nodeValue = formatNumber(frame.time_s, 8); metrics[1].nodeValue = (frameIndex + 1) + ' / ' + frames().length; metrics[2].nodeValue = formatNumber(frame.total_energy_j, 8);
    first.disabled = previous.disabled = frameIndex === 0;
    next.disabled = last.disabled = frameIndex === frames().length - 1;
    updateGraph(); drawScene();
  }
  function diagnosticRow(label, value) { const row = el('div'); row.append(el('dt', '', label), el('dd', '', value)); diagnosticValues.append(row); }
  function chooseLeg(index) {
    pause(); legIndex = index; frameIndex = 0; legSelect.value = String(index);
    camera = cameraForFrames(frames());
    range.max = String(frames().length - 1); range.disabled = frames().length <= 1; play.disabled = frames().length <= 1;
    warning.hidden = !model.partial && leg().stop_reason === 'completed';
    warning.textContent = '이 실행에는 부분 결과가 있습니다. 선택 궤적 종료 사유: ' + leg().stop_reason + '. 마지막 수락 프레임까지 표시하며 성공 최종 상태와 구분하세요.';
    const span = frames().at(-1).time_s - frames()[0].time_s;
    playbackNote.textContent = '물리 구간 ' + formatNumber(span, 10) + ' s를 화면 ' + (8 / Number(speed.value)) + '초에 재생합니다. 저장 프레임을 시각에 맞춰 유지하며 보간하지 않습니다.';
    cameraNote.textContent = '표시 원점 (m): [' + camera.origin.map(exact).join(', ') + '] · 정규화 길이: ' + exact(camera.scale_m) + ' m. 카메라는 선택 궤적 전체에 고정됩니다.';
    diagnosticValues.replaceChildren();
    diagnosticRow('수락한 계산 스텝 / 요청', leg().completed_steps + ' / ' + leg().requested_steps);
    diagnosticRow('완료한 힘 평가', String(leg().completed_force_evaluations));
    diagnosticRow('에너지 최대 scaled 편차', exact(leg().max_energy_drift_scaled));
    diagnosticRow('운동량 최대 scaled 편차', exact(leg().max_momentum_drift_scaled));
    diagnosticRow('각운동량 최대 scaled 편차', exact(leg().max_angular_momentum_drift_scaled));
    diagnosticRow('질량중심 최대 scaled 편차', exact(leg().max_com_ballistic_error_scaled));
    diagnosticRow('시간간격 비교', statusLabel(payload.resolution_comparison?.status));
    buildGraph(); resetCamera(); selectFrame(0);
  }
  function tick(now) {
    raf = 0;
    if (!playing || !active()) { pause(); return; }
    if (startedAt === null) startedAt = now;
    const fraction = Math.min(1, startedFraction + (now - startedAt) / (8000 / Number(speed.value)));
    selectFrame(selectFrameAtFraction(frames(), fraction));
    if (fraction >= 1) { selectFrame(frames().length - 1); pause(); }
    else raf = win.requestAnimationFrame(tick);
  }
  function togglePlay() {
    if (playing) { pause(); return; }
    if (frames().length < 2 || !active()) return;
    if (frameIndex === frames().length - 1) selectFrame(0);
    playing = true; startedAt = null; startedFraction = fractionAtFrame(frames(), frameIndex);
    play.textContent = '정지'; play.setAttribute('aria-label', '궤적 재생 정지'); play.setAttribute('aria-pressed', 'true');
    raf = win.requestAnimationFrame(tick);
  }
  function moveFrame(index) { pause(); selectFrame(index); }
  listen(first, 'click', () => moveFrame(0));
  listen(previous, 'click', () => moveFrame(frameIndex - 1));
  listen(next, 'click', () => moveFrame(frameIndex + 1));
  listen(last, 'click', () => moveFrame(frames().length - 1));
  listen(play, 'click', togglePlay);
  listen(range, 'input', () => moveFrame(Number(range.value)));
  listen(particleSelect, 'change', () => { particleIndex = Number(particleSelect.value); selectFrame(frameIndex); });
  listen(legSelect, 'change', () => chooseLeg(Number(legSelect.value)));
  listen(graphSelect, 'change', () => { buildGraph(); updateGraph(); });
  listen(speed, 'change', () => {
    startedAt = null; startedFraction = fractionAtFrame(frames(), frameIndex);
    const span = frames().at(-1).time_s - frames()[0].time_s;
    playbackNote.textContent = '물리 구간 ' + formatNumber(span, 10) + ' s를 화면 ' + (8 / Number(speed.value)) + '초에 재생합니다. 저장 프레임을 시각에 맞춰 유지하며 보간하지 않습니다.';
  });
  listen(reset, 'click', resetCamera);
  listen(zoomIn, 'click', () => setZoom(zoom * 1.3));
  listen(zoomOut, 'click', () => setZoom(zoom / 1.3));
  listen(pathToggle, 'change', drawScene);
  function mode(value) { dragMode = value; orbitButton.setAttribute('aria-pressed', String(value === 'orbit')); panButton.setAttribute('aria-pressed', String(value === 'pan')); }
  listen(orbitButton, 'click', () => mode('orbit'));
  listen(panButton, 'click', () => mode('pan'));
  listen(canvas, 'wheel', event => { event.preventDefault(); setZoom(zoom * Math.exp(-clamp(event.deltaY, -200, 200) * .002)); }, {passive: false});
  listen(canvas, 'contextmenu', event => event.preventDefault());
  listen(canvas, 'keydown', event => {
    if (event.key === 'Home') { event.preventDefault(); resetCamera(); return; }
    if (event.key === '+' || event.key === '=') { event.preventDefault(); setZoom(zoom * 1.2); return; }
    if (event.key === '-') { event.preventDefault(); setZoom(zoom / 1.2); return; }
    if (event.key === ' ') { event.preventDefault(); togglePlay(); return; }
    const directions = {ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1]};
    const delta = directions[event.key];
    if (!delta) return;
    event.preventDefault();
    if (event.shiftKey) { panX = clamp(panX + delta[0] * 16, -screenWidth * 20, screenWidth * 20); panY = clamp(panY + delta[1] * 16, -screenHeight * 20, screenHeight * 20); }
    else { yaw += delta[0] * .12; pitch = clamp(pitch + delta[1] * .12, -Math.PI / 2, Math.PI / 2); }
    drawScene();
  });
  listen(canvas, 'pointerdown', event => {
    if (!context) return;
    if (event.button !== 0 && event.button !== 2) return;
    canvas.focus({preventScroll: true});
    try { canvas.setPointerCapture(event.pointerId); } catch { /* capture can be unavailable after cancellation */ }
    pointers.set(event.pointerId, {x: event.clientX, y: event.clientY, startX: event.clientX, startY: event.clientY});
    moved = pointers.size > 1;
  });
  listen(canvas, 'pointermove', event => {
    const old = pointers.get(event.pointerId); if (!old) return;
    const dx = event.clientX - old.x, dy = event.clientY - old.y;
    const before = [...pointers.values()];
    if (Math.hypot(event.clientX - old.startX, event.clientY - old.startY) > 4) moved = true;
    pointers.set(event.pointerId, {...old, x: event.clientX, y: event.clientY});
    if (pointers.size >= 2) {
      moved = true;
      const after = [...pointers.values()];
      const oldDistance = Math.hypot(before[0].x - before[1].x, before[0].y - before[1].y);
      const newDistance = Math.hypot(after[0].x - after[1].x, after[0].y - after[1].y);
      if (oldDistance > 1 && newDistance > 1) zoom = clamp(zoom * newDistance / oldDistance, .15, 40);
      panX += (after[0].x + after[1].x - before[0].x - before[1].x) / 2;
      panY += (after[0].y + after[1].y - before[0].y - before[1].y) / 2;
    } else if (dragMode === 'pan' || event.shiftKey || event.buttons === 2) { panX += dx; panY += dy; }
    else { yaw = (yaw + dx * .008) % (2 * Math.PI); pitch = clamp(pitch + dy * .008, -Math.PI / 2, Math.PI / 2); }
    panX = clamp(panX, -screenWidth * 20, screenWidth * 20); panY = clamp(panY, -screenHeight * 20, screenHeight * 20);
    drawScene();
  });
  const release = event => {
    if (!pointers.has(event.pointerId)) return;
    const click = !moved && event.type === 'pointerup' && pointers.size === 1;
    pointers.delete(event.pointerId);
    try { if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId); } catch { /* already released */ }
    if (click) {
      const rect = canvas.getBoundingClientRect();
      const x = (event.clientX - rect.left) * screenWidth / rect.width;
      const y = (event.clientY - rect.top) * screenHeight / rect.height;
      const point = [...screenPoints].reverse().find(p => Math.hypot(p.x - x, p.y - y) <= 13);
      if (point) { particleIndex = point.index; particleSelect.value = String(particleIndex); selectFrame(frameIndex); }
    }
  };
  listen(canvas, 'pointerup', release); listen(canvas, 'pointercancel', release); listen(canvas, 'lostpointercapture', release);
  listen(canvas, 'contextlost', event => {
    event.preventDefault(); pause(); context = null; canvas.hidden = true; fallback.hidden = false;
    for (const control of [orbitButton, panButton, zoomOut, zoomIn, reset, pathToggle]) control.disabled = true;
  });
  listen(doc, 'visibilitychange', () => { if (doc.hidden) pause(); });
  if (typeof win.ResizeObserver === 'function') { observer = new win.ResizeObserver(resize); observer.observe(scene); }
  else listen(win, 'resize', resize);
  chooseLeg(legIndex); resize();
  return {
    pause,
    dispose() {
      if (disposed) return;
      pause(); disposed = true; observer?.disconnect(); listeners.forEach(remove => remove());
      pointers.clear(); screenPoints = []; graphView = null;
      ownNodes.forEach(item => item.remove());
    },
  };
}
