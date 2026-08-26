# Nekomimi Portrait Asset

## 1. Scope

This specification governs the two files `assets/nekomimi-portrait.svg` and
`assets/nekomimi-portrait.html`. The asset is a static illustration. It has no runtime
dependency on any other subsystem, and no other subsystem may import it as code.

## 2. File constraints

### 2.1 `assets/nekomimi-portrait.svg`

- The root element is `<svg>` with `viewBox="0 0 800 800"`, `width="800"` and `height="800"`.
- The document declares `xmlns="http://www.w3.org/2000/svg"` and no other namespace.
- The document is well formed XML. `xml.dom.minidom.parse` on the file must not raise.
- The document contains exactly zero `<image>` elements. No element carries an `href` or
  `xlink:href` attribute whose value is a raster resource, a `data:` URI, or an external URL.
- Every drawing element is one of `path`, `circle`, `ellipse`, `rect`, `use`, `g`, `pattern`,
  `linearGradient`, `radialGradient`, `clipPath`, `mask`, `filter`, `stop`, `feTurbulence`,
  `feDisplacementMap`, `title` or `desc`.
- All geometry is authored by hand. No path data in this file may be produced by an
  image tracing tool (`potrace`, `autotrace`, `convert -trace`, or equivalent).
- The root element carries `role="img"` and `aria-labelledby` referencing a `<title>` and a
  `<desc>` element.

### 2.2 `assets/nekomimi-portrait.html`

- The document embeds the SVG through `<object type="image/svg+xml" data="nekomimi-portrait.svg">`.
- The `<object>` element carries a non-empty `aria-label`.
- The embedding container has a `1 / 1` aspect ratio, so the SVG renders without distortion.
- The file references no resource outside `assets/`.

## 3. Palette

The following colours are fixed. Other colours in the file are tints, shades or gradient
stops derived from them.

| Role | Value |
| --- | --- |
| Paper | `#fbf1de` |
| Disc | `#e8644c` |
| Brush stroke | `#4c84c4` |
| Uniform navy | `#0b3065` to `#154382` |
| Hair highlight | `#fbfaf6` |
| Hair shadow | `#c9d7ec` |
| Skin | `#fdeada` to `#f7d6bf` |
| Offset plate | `#ef8570` |

## 4. Composition

Coordinates are in viewBox units.

- The disc is centred at `(399, 350)` with radius `245`. A halftone ring of radius `252`
  extends past it, and both are displaced by the `roughDisc` filter.
- Sixteen brush dabs are drawn. Ten form the right cluster, bounded by
  `x in [560, 770]` and `y in [105, 625]`. Six form the left cluster, bounded by
  `x in [45, 225]` and `y in [355, 625]`.
- The hair silhouette spans `x in [192, 588]` and `y in [114, 540]`.
- The face silhouette spans `x in [325, 506]` and `y in [296, 500]`.
- The left iris is centred at `(341, 375)`, the right iris at `(477, 360)`.
- The sailor collar occupies `y in [510, 714]`. Its two panels meet near `(443, 702)`.
- The neckerchief knot occupies `x in [410, 487]` and `y in [696, 748]`.
- The lily is centred at `(556, 252)` and has six petals.

## 5. Halftone

- Four `<pattern>` elements provide the halftone screens: `htRed`, `htRedTex`, `htBlue`
  and `htNavy`.
- Each pattern tile is `3.4 x 3.4` user units and holds two circles placed at
  `(0.85, 0.85)` and `(2.55, 2.55)`, which produces a 45 degree dot grid.
- Circle radius is `0.95` for `htRed` and `htBlue`, `0.9` for `htNavy`, and `0.8` for
  `htRedTex`.
- Each pattern carries a `patternTransform` rotation, so the screens of different inks do
  not moire against each other: `18deg` for the red screens, `-14deg` for blue, `30deg`
  for navy.
- The disc and every brush dab are covered by a halftone screen. The blue dabs are drawn
  twice: a halftone pass six units wider than the nominal dab width supplies the dotted
  dry fringe, and a solid pass four units narrower supplies the wet core.

## 6. Layer order

Elements are painted in this order. Later entries occlude earlier entries.

1. Paper rectangle.
2. Blue brush strokes, inside a group with `mix-blend-mode: multiply`.
3. Red halftone disc.
4. Ribbon tails.
5. Hair mass behind the head.
6. Neck, chest and face.
7. Face features.
8. Uniform, masked by `fadeM`.
9. Hair in front: side locks, fringe, strand detail.
10. Cat ears.
11. Bow and lily.

The ears are painted after the front hair. Painting them earlier hides their lower half
behind the side locks and is a defect.

## 7. Torso fade

- The `fadeM` mask applies a vertical gradient in user space from `y = 660` to `y = 766`.
- Mask luminance is `1.0` at `y <= 660`, at least `0.92` at `y = 724`, at least `0.70` at
  `y = 747`, and `0` at `y >= 766`.
- Consequently the neckerchief knot remains visible along its whole height, and no torso
  edge is visible at `y >= 766`.

## 8. Verification

A change to either file is accepted only when all of the following hold.

1. `python3 -c "import xml.dom.minidom; xml.dom.minidom.parse('assets/nekomimi-portrait.svg')"`
   exits with status 0.
2. `grep -c '<image' assets/nekomimi-portrait.svg` reports 0.
3. Rendering `assets/nekomimi-portrait.html` in a Chromium based browser at a viewport of
   at least `1000 x 1050` produces a portrait with no clipped element and no scrollbar.
