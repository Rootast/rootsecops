import { ImageResponse } from "next/og";

export const size = { width: 64, height: 64 };
export const contentType = "image/png";

export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#09090b",
          color: "#34d399",
          border: "3px solid #34d399",
          borderRadius: 8,
          fontSize: 32,
          fontWeight: 700,
          letterSpacing: 0,
        }}
      >
        RS
      </div>
    ),
    size
  );
}
