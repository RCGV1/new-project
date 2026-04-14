"use client";

import { toPng } from "html-to-image";
import { CSSProperties, ReactNode, useEffect, useMemo, useRef, useState } from "react";

const W = 1320;
const H = 2868;

const IPHONE_SIZES = [
  { label: '6.9"', w: 1320, h: 2868 },
  { label: '6.5"', w: 1284, h: 2778 },
  { label: '6.3"', w: 1206, h: 2622 },
  { label: '6.1"', w: 1179, h: 2556 },
] as const;

const LOCALES = ["en"] as const;
type Locale = (typeof LOCALES)[number];

const THEMES = {
  midnightSignal: {
    bg: "#050816",
    bg2: "#121b34",
    bg3: "#1f3658",
    card: "rgba(15, 21, 39, 0.78)",
    fg: "#f8fbff",
    muted: "#9eaccd",
    accent: "#53a3ff",
    accent2: "#85f4ff",
    glow: "rgba(83, 163, 255, 0.24)",
  },
  carbonBlue: {
    bg: "#08111f",
    bg2: "#183154",
    bg3: "#29476b",
    card: "rgba(8, 15, 31, 0.8)",
    fg: "#f3f7fe",
    muted: "#97a8c6",
    accent: "#5ea0ff",
    accent2: "#ffb65c",
    glow: "rgba(94, 160, 255, 0.22)",
  },
  auroraNight: {
    bg: "#09111d",
    bg2: "#214659",
    bg3: "#1e6b72",
    card: "rgba(12, 22, 34, 0.78)",
    fg: "#f5fbff",
    muted: "#97b1bf",
    accent: "#71c7ff",
    accent2: "#6effcb",
    glow: "rgba(110, 255, 203, 0.2)",
  },
} as const;

type ThemeId = keyof typeof THEMES;

type SlideCopy = {
  id: string;
  label: string;
  title: ReactNode;
  body: string;
  src: string;
  kicker: string;
  secondarySrc?: string;
  secondaryLabel?: string;
};

const COPY: Record<Locale, SlideCopy[]> = {
  en: [
    {
      id: "hero",
      label: "FIELDHT",
      title: (
        <>
          Control your
          <br />
          radio fast.
        </>
      ),
      body: "Change channels, see active lines, and adjust live controls from one sharp screen on iPhone.",
      src: "/screenshots/en/radio.png",
      kicker: "Radio control",
    },
    {
      id: "connect",
      label: "PAIRING",
      title: (
        <>
          Connect in
          <br />
          seconds.
        </>
      ),
      body: "Find the radio, reconnect quickly, and get back to operation without digging through hardware menus.",
      src: "/screenshots/en/connect.png",
      kicker: "Fast link",
      secondarySrc: "/screenshots/en/radio.png",
      secondaryLabel: "Control preview",
    },
    {
      id: "channels",
      label: "CHANNELS",
      title: (
        <>
          Build channel
          <br />
          plans faster.
        </>
      ),
      body: "Manage groups, import from CSV or documents, and load clean memory channels without keypad work.",
      src: "/screenshots/en/channels.png",
      kicker: "Channel setup",
    },
    {
      id: "setup",
      label: "SETUP",
      title: (
        <>
          Tune buttons
          <br />
          and audio.
        </>
      ),
      body: "Set squelch, mic gain, APRS, speaker-mic behavior, and programmable button actions from one place.",
      src: "/screenshots/en/settings.png",
      kicker: "Settings",
      secondarySrc: "/screenshots/en/buttons.png",
      secondaryLabel: "Programmable buttons",
    },
    {
      id: "satellite",
      label: "SATELLITE",
      title: (
        <>
          Track passes
          <br />
          live.
        </>
      ),
      body: "Watch orbit position, keep the radio plan in view, and follow RX/TX updates while the pass unfolds.",
      src: "/screenshots/en/satellite.png",
      kicker: "Mission mode",
    },
  ],
};

const imageCache: Record<string, string> = {};
const ALL_IMAGE_PATHS = [
  "/app-icon.png",
  "/screenshots/en/radio.png",
  "/screenshots/en/connect.png",
  "/screenshots/en/channels.png",
  "/screenshots/en/settings.png",
  "/screenshots/en/buttons.png",
  "/screenshots/en/satellite.png",
];

function img(path: string): string {
  return imageCache[path] || path;
}

async function preloadAllImages() {
  await Promise.all(
    ALL_IMAGE_PATHS.map(async (path) => {
      if (imageCache[path]) {
        return;
      }

      const response = await fetch(path);
      const blob = await response.blob();
      const dataUrl = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result as string);
        reader.readAsDataURL(blob);
      });
      imageCache[path] = dataUrl;
    }),
  );
}

function captionStyles(cW: number, theme: (typeof THEMES)[ThemeId]) {
  return {
    label: {
      fontSize: cW * 0.025,
      letterSpacing: `${cW * 0.0022}px`,
      color: theme.accent2,
      fontWeight: 700,
      textTransform: "uppercase" as const,
    },
    title: {
      fontSize: cW * 0.09,
      lineHeight: 0.92,
      letterSpacing: `${-cW * 0.0016}px`,
      color: theme.fg,
      fontWeight: 800,
    },
    body: {
      fontSize: cW * 0.028,
      lineHeight: 1.38,
      color: theme.muted,
      maxWidth: cW * 0.47,
    },
  };
}

function GradientBlob({
  style,
  color,
}: {
  style: CSSProperties;
  color: string;
}) {
  return (
    <div
      style={{
        position: "absolute",
        borderRadius: 999,
        filter: "blur(46px)",
        opacity: 0.88,
        background: color,
        ...style,
      }}
    />
  );
}

function GlassCard({
  children,
  style,
  theme,
}: {
  children: ReactNode;
  style?: CSSProperties;
  theme: (typeof THEMES)[ThemeId];
}) {
  return (
    <div
      style={{
        position: "absolute",
        background: `linear-gradient(180deg, ${theme.card} 0%, rgba(8, 14, 26, 0.92) 100%)`,
        border: "1px solid rgba(255,255,255,0.08)",
        boxShadow: `0 24px 80px ${theme.glow}`,
        borderRadius: 36,
        overflow: "hidden",
        ...style,
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: 36,
          boxShadow: "inset 0 1px 0 rgba(255,255,255,0.08)",
          pointerEvents: "none",
        }}
      />
      {children}
    </div>
  );
}

function ScreenCard({
  src,
  alt,
  style,
  radius = 62,
}: {
  src: string;
  alt: string;
  style?: CSSProperties;
  radius?: number;
}) {
  return (
    <div
      style={{
        position: "absolute",
        aspectRatio: "1179 / 2556",
        borderRadius: radius,
        overflow: "hidden",
        background: "#000",
        border: "1px solid rgba(255,255,255,0.08)",
        boxShadow: "0 48px 110px rgba(0,0,0,0.56)",
        ...style,
      }}
    >
      <img
        src={img(src)}
        alt={alt}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
          objectFit: "cover",
          objectPosition: "top",
        }}
        draggable={false}
      />
    </div>
  );
}

function StatusPill({
  text,
  theme,
  icon,
}: {
  text: string;
  theme: (typeof THEMES)[ThemeId];
  icon?: string;
}) {
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 10,
        padding: "12px 18px",
        borderRadius: 999,
        background: "rgba(255,255,255,0.06)",
        border: "1px solid rgba(255,255,255,0.08)",
        color: theme.fg,
        fontSize: 22,
        fontWeight: 600,
      }}
    >
      {icon ? <span style={{ color: theme.accent2 }}>{icon}</span> : null}
      <span>{text}</span>
    </div>
  );
}

function SlideCanvas({
  slideIndex,
  locale,
  cW,
  cH,
  themeId,
}: {
  slideIndex: number;
  locale: Locale;
  cW: number;
  cH: number;
  themeId: ThemeId;
}) {
  const theme = THEMES[themeId];
  const content = COPY[locale][slideIndex];
  const styles = captionStyles(cW, theme);

  const commonWrap: CSSProperties = {
    width: "100%",
    height: "100%",
    position: "relative",
    overflow: "hidden",
    background: `radial-gradient(circle at top left, ${theme.bg2} 0%, ${theme.bg} 62%)`,
  };

  if (slideIndex === 0) {
    return (
      <div style={commonWrap}>
        <GradientBlob
          color={theme.glow}
          style={{ width: cW * 0.46, height: cW * 0.46, top: -cW * 0.16, left: -cW * 0.08 }}
        />
        <GradientBlob
          color={theme.accent}
          style={{ width: cW * 0.34, height: cW * 0.34, right: -cW * 0.06, bottom: cW * 0.34, opacity: 0.26 }}
        />

        <div style={{ position: "absolute", top: "6.4%", left: "7.2%", zIndex: 3 }}>
          <div style={styles.label}>{content.label}</div>
          <div style={{ height: cW * 0.024 }} />
          <div style={styles.title}>{content.title}</div>
          <div style={{ height: cW * 0.034 }} />
          <div style={styles.body}>{content.body}</div>
        </div>

        <GlassCard
          theme={theme}
          style={{ top: "6.4%", right: "6.2%", padding: "18px 20px", zIndex: 3 }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <img
              src={img("/app-icon.png")}
              alt="FieldHT icon"
              style={{ width: 70, height: 70, borderRadius: 18 }}
              draggable={false}
            />
            <div>
              <div style={{ color: theme.fg, fontSize: 28, fontWeight: 700 }}>FieldHT</div>
              <div style={{ color: theme.muted, fontSize: 20 }}>Bluetooth radio control</div>
            </div>
          </div>
        </GlassCard>

        <GlassCard
          theme={theme}
          style={{
            left: "7.2%",
            bottom: "12%",
            padding: "24px 28px",
            width: "38%",
            zIndex: 3,
          }}
        >
          <div style={{ color: theme.muted, fontSize: 20, letterSpacing: 1.6, textTransform: "uppercase" }}>
            Built for field use
          </div>
          <div style={{ marginTop: 14, color: theme.fg, fontSize: 34, lineHeight: 1.08, fontWeight: 700 }}>
            Channels. Audio.
            <br />
            One clear screen.
          </div>
        </GlassCard>

        <ScreenCard
          src={content.src}
          alt={content.kicker}
          style={{
            width: "66%",
            right: "-3%",
            bottom: "-9%",
            transform: "rotate(-4deg)",
            zIndex: 2,
          }}
        />
      </div>
    );
  }

  if (slideIndex === 1) {
    return (
      <div style={commonWrap}>
        <GradientBlob
          color={theme.glow}
          style={{ width: cW * 0.32, height: cW * 0.32, top: cW * 0.16, right: -cW * 0.08 }}
        />
        <div style={{ position: "absolute", top: "8.2%", left: "8%", zIndex: 3 }}>
          <div style={styles.label}>{content.label}</div>
          <div style={{ height: cW * 0.02 }} />
          <div style={styles.title}>{content.title}</div>
          <div style={{ height: cW * 0.028 }} />
          <div style={{ ...styles.body, maxWidth: cW * 0.4 }}>{content.body}</div>
        </div>

        <GlassCard
          theme={theme}
          style={{ top: "7.8%", right: "7.2%", padding: "18px 20px", zIndex: 3 }}
        >
          <StatusPill text="UV-PRO linked" theme={theme} icon="●" />
        </GlassCard>

        <GlassCard
          theme={theme}
          style={{
            top: "27%",
            right: "7.2%",
            width: "34%",
            padding: "24px 26px",
            zIndex: 3,
          }}
        >
          <div style={{ color: theme.fg, fontSize: 34, fontWeight: 700, lineHeight: 1.06 }}>
            Ready before
            <br />
            the next call.
          </div>
          <div style={{ marginTop: 16, color: theme.muted, fontSize: 22, lineHeight: 1.4 }}>
            Keep the radio paired and jump straight back into control.
          </div>
        </GlassCard>

        <ScreenCard
          src={content.src}
          alt={content.kicker}
          style={{
            width: "54%",
            left: "-6%",
            bottom: "-4%",
            transform: "rotate(-8deg)",
            zIndex: 1,
            opacity: 0.96,
          }}
        />
        <ScreenCard
          src={content.secondarySrc || content.src}
          alt={content.secondaryLabel || content.kicker}
          style={{
            width: "50%",
            right: "2%",
            bottom: "-6%",
            transform: "rotate(7deg)",
            zIndex: 2,
          }}
        />
      </div>
    );
  }

  if (slideIndex === 2) {
    return (
      <div
        style={{
          ...commonWrap,
          background: `linear-gradient(180deg, ${theme.bg2} 0%, ${theme.bg} 44%, #07101d 100%)`,
        }}
      >
        <GradientBlob
          color={theme.glow}
          style={{ width: cW * 0.42, height: cW * 0.42, left: -cW * 0.08, bottom: cW * 0.18 }}
        />

        <div style={{ position: "absolute", top: "7.6%", left: "7.2%", zIndex: 3 }}>
          <div style={styles.label}>{content.label}</div>
          <div style={{ height: cW * 0.022 }} />
          <div style={styles.title}>{content.title}</div>
          <div style={{ height: cW * 0.028 }} />
          <div style={{ ...styles.body, maxWidth: cW * 0.42 }}>{content.body}</div>
        </div>

        <GlassCard
          theme={theme}
          style={{
            left: "7.2%",
            bottom: "13%",
            width: "40%",
            padding: "24px 26px",
            zIndex: 3,
          }}
        >
          <div style={{ display: "grid", gap: 14 }}>
            <StatusPill text="Import from CSV" theme={theme} icon="↥" />
            <StatusPill text="Import from document" theme={theme} icon="▣" />
            <StatusPill text="Manage groups" theme={theme} icon="◎" />
          </div>
        </GlassCard>

        <ScreenCard
          src={content.src}
          alt={content.kicker}
          style={{
            width: "58%",
            right: "2%",
            bottom: "-7%",
            zIndex: 2,
          }}
        />
      </div>
    );
  }

  if (slideIndex === 3) {
    return (
      <div
        style={{
          ...commonWrap,
          background: `linear-gradient(180deg, #0b1523 0%, ${theme.bg2} 46%, #08111d 100%)`,
        }}
      >
        <GradientBlob
          color={theme.glow}
          style={{ width: cW * 0.36, height: cW * 0.36, right: -cW * 0.08, top: cW * 0.22 }}
        />

        <div style={{ position: "absolute", top: "7.8%", left: "7.2%", zIndex: 3 }}>
          <div style={styles.label}>{content.label}</div>
          <div style={{ height: cW * 0.022 }} />
          <div style={styles.title}>{content.title}</div>
        </div>

        <GlassCard
          theme={theme}
          style={{
            left: "7.2%",
            top: "30%",
            width: "38%",
            padding: "24px 26px",
            zIndex: 3,
          }}
        >
          <div style={{ display: "grid", gap: 14 }}>
            <StatusPill text="Squelch + mic gain" theme={theme} icon="↔" />
            <StatusPill text="APRS controls" theme={theme} icon="△" />
            <StatusPill text="Button actions" theme={theme} icon="◍" />
          </div>
        </GlassCard>

        <div
          style={{
            position: "absolute",
            left: "7.2%",
            bottom: "14%",
            width: "38%",
            color: theme.muted,
            fontSize: 22,
            lineHeight: 1.45,
            zIndex: 3,
          }}
        >
          {content.body}
        </div>

        <ScreenCard
          src={content.src}
          alt={content.kicker}
          style={{
            width: "46%",
            right: "3%",
            bottom: "-7%",
            transform: "rotate(3deg)",
            zIndex: 2,
          }}
        />

        <ScreenCard
          src={content.secondarySrc || content.src}
          alt={content.secondaryLabel || content.kicker}
          radius={42}
          style={{
            width: "24%",
            right: "38%",
            bottom: "13%",
            transform: "rotate(-6deg)",
            zIndex: 4,
          }}
        />
      </div>
    );
  }

  return (
    <div
      style={{
        ...commonWrap,
        background: "linear-gradient(180deg, #0b1523 0%, #13253c 52%, #08111d 100%)",
      }}
    >
      <GradientBlob
        color={theme.glow}
        style={{ width: cW * 0.4, height: cW * 0.4, right: -cW * 0.12, top: cW * 0.2 }}
      />
      <div style={{ position: "absolute", top: "7.6%", left: "7.2%", zIndex: 3 }}>
        <div style={styles.label}>{content.label}</div>
        <div style={{ height: cW * 0.02 }} />
        <div style={styles.title}>{content.title}</div>
        <div style={{ height: cW * 0.03 }} />
        <div style={{ ...styles.body, maxWidth: cW * 0.42 }}>{content.body}</div>
      </div>

      <GlassCard
        theme={theme}
        style={{
          left: "7.2%",
          bottom: "14%",
          padding: "22px 24px",
          zIndex: 3,
        }}
      >
        <div style={{ color: theme.fg, fontSize: 24, fontWeight: 700, marginBottom: 12 }}>Live plan</div>
        <div style={{ display: "grid", gap: 10 }}>
          <StatusPill text="RX + TX updates" theme={theme} icon="◐" />
          <StatusPill text="Orbit at a glance" theme={theme} icon="◌" />
        </div>
      </GlassCard>

      <ScreenCard
        src={content.src}
        alt={content.kicker}
        style={{
          width: "54%",
          right: "4%",
          bottom: "-5%",
          zIndex: 2,
        }}
      />
    </div>
  );
}

function ScreenshotPreview({
  children,
  cW,
  cH,
}: {
  children: ReactNode;
  cW: number;
  cH: number;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scale, setScale] = useState(0.2);

  useEffect(() => {
    const node = containerRef.current;
    if (!node) {
      return;
    }

    const observer = new ResizeObserver(([entry]) => {
      const nextScale = Math.min(entry.contentRect.width / cW, 1);
      setScale(nextScale);
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [cW]);

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        borderRadius: 24,
        background: "#0b1020",
        padding: 18,
        overflow: "hidden",
        border: "1px solid rgba(255,255,255,0.06)",
      }}
    >
      <div
        style={{
          width: cW,
          height: cH,
          transform: `scale(${scale})`,
          transformOrigin: "top left",
          borderRadius: 28,
          overflow: "hidden",
          boxShadow: "0 24px 60px rgba(0,0,0,0.4)",
          marginBottom: -(cH * (1 - scale)),
        }}
      >
        {children}
      </div>
    </div>
  );
}

async function captureSlide(el: HTMLElement, w: number, h: number): Promise<string> {
  el.style.left = "0px";
  el.style.opacity = "1";
  el.style.zIndex = "-1";

  const opts = { width: w, height: h, pixelRatio: 1, cacheBust: true };
  await toPng(el, opts);
  const dataUrl = await toPng(el, opts);

  el.style.left = "-9999px";
  el.style.opacity = "";
  el.style.zIndex = "";

  return dataUrl;
}

export default function Home() {
  const [ready, setReady] = useState(false);
  const [locale, setLocale] = useState<Locale>("en");
  const [themeId, setThemeId] = useState<ThemeId>("midnightSignal");
  const [sizeIdx, setSizeIdx] = useState(0);
  const [exporting, setExporting] = useState<string | null>(null);
  const exportRefs = useRef<Array<HTMLDivElement | null>>([]);

  useEffect(() => {
    preloadAllImages().then(() => setReady(true));
  }, []);

  const slides = useMemo(() => COPY[locale], [locale]);
  const currentSize = IPHONE_SIZES[sizeIdx];

  const exportAll = async () => {
    for (let i = 0; i < slides.length; i += 1) {
      const el = exportRefs.current[i];
      if (!el) {
        continue;
      }

      setExporting(`${i + 1}/${slides.length}`);
      const dataUrl = await captureSlide(el, currentSize.w, currentSize.h);
      const anchor = document.createElement("a");
      anchor.href = dataUrl;
      anchor.download = `${String(i + 1).padStart(2, "0")}-${slides[i].id}-${locale}-${currentSize.w}x${currentSize.h}.png`;
      anchor.click();
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    setExporting(null);
  };

  if (!ready) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          background: "#060b16",
          color: "#eff5ff",
        }}
      >
        Loading screenshot assets…
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "linear-gradient(180deg, #09111f 0%, #050812 100%)",
        position: "relative",
        overflowX: "hidden",
      }}
    >
        <div
          style={{
            position: "sticky",
            top: 0,
            zIndex: 50,
            background: "rgba(5,10,20,0.92)",
            backdropFilter: "blur(18px)",
            borderBottom: "1px solid rgba(255,255,255,0.08)",
            display: "flex",
            alignItems: "center",
          }}
        >
          <div
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "12px 18px",
              overflowX: "auto",
              minWidth: 0,
            }}
          >
            <span style={{ fontWeight: 800, fontSize: 14, whiteSpace: "nowrap", color: "#f4f8ff" }}>
              FieldHT App Store Screens
            </span>

            <select
              value={locale}
              onChange={(e) => setLocale(e.target.value as Locale)}
              style={{
                fontSize: 12,
                border: "1px solid rgba(255,255,255,0.12)",
                borderRadius: 8,
                padding: "6px 10px",
                background: "#0e1629",
                color: "#f4f8ff",
              }}
            >
              {LOCALES.map((item) => (
                <option key={item} value={item}>
                  {item.toUpperCase()}
                </option>
              ))}
            </select>

            <select
              value={themeId}
              onChange={(e) => setThemeId(e.target.value as ThemeId)}
              style={{
                fontSize: 12,
                border: "1px solid rgba(255,255,255,0.12)",
                borderRadius: 8,
                padding: "6px 10px",
                background: "#0e1629",
                color: "#f4f8ff",
              }}
            >
              <option value="midnightSignal">Midnight Signal</option>
              <option value="carbonBlue">Carbon Blue</option>
              <option value="auroraNight">Aurora Night</option>
            </select>

            <select
              value={sizeIdx}
              onChange={(e) => setSizeIdx(Number(e.target.value))}
              style={{
                fontSize: 12,
                border: "1px solid rgba(255,255,255,0.12)",
                borderRadius: 8,
                padding: "6px 10px",
                background: "#0e1629",
                color: "#f4f8ff",
              }}
            >
              {IPHONE_SIZES.map((size, index) => (
                <option key={size.label} value={index}>
                  {size.label} — {size.w}×{size.h}
                </option>
              ))}
            </select>
          </div>

          <div style={{ flexShrink: 0, padding: "12px 18px", borderLeft: "1px solid rgba(255,255,255,0.08)" }}>
            <button
              onClick={exportAll}
              disabled={!!exporting}
              style={{
                padding: "9px 20px",
                background: exporting ? "#77aef5" : "#3d8dff",
                color: "white",
                border: "none",
                borderRadius: 10,
                fontSize: 12,
                fontWeight: 700,
                cursor: exporting ? "default" : "pointer",
                whiteSpace: "nowrap",
              }}
            >
              {exporting ? `Exporting… ${exporting}` : "Export All"}
            </button>
          </div>
        </div>

      <main style={{ padding: "32px 22px 72px", maxWidth: 1560, margin: "0 auto" }}>
        <div style={{ marginBottom: 24 }}>
          <div style={{ color: "#f5f8ff", fontSize: 30, fontWeight: 800 }}>5-slide iPhone set</div>
          <div style={{ color: "#96a7c7", fontSize: 16, marginTop: 8, maxWidth: 920, lineHeight: 1.5 }}>
            Narrative arc: control, connect, build channels, tune setup, then run satellite mode. The
            compositions are tighter now, with larger screens and rounded screenshot cards instead of the
            previous framed treatment.
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(290px, 1fr))",
            gap: 18,
          }}
        >
          {slides.map((slide, index) => (
            <div key={slide.id}>
              <div style={{ color: "#f4f8ff", fontSize: 15, fontWeight: 700, marginBottom: 10 }}>
                {String(index + 1).padStart(2, "0")}. {slide.id}
              </div>
              <ScreenshotPreview cW={W} cH={H}>
                <SlideCanvas slideIndex={index} locale={locale} cW={W} cH={H} themeId={themeId} />
              </ScreenshotPreview>
            </div>
          ))}
        </div>

        <div style={{ position: "absolute", left: -9999, top: 0, opacity: 0 }}>
          {slides.map((slide, index) => (
            <div
              key={`export-${slide.id}`}
              ref={(node) => {
                exportRefs.current[index] = node;
              }}
              style={{
                position: "absolute",
                left: -9999,
                width: W,
                height: H,
                borderRadius: 28,
                overflow: "hidden",
              }}
            >
              <SlideCanvas slideIndex={index} locale={locale} cW={W} cH={H} themeId={themeId} />
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
