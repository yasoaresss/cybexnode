import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CybexNode BR — Monitoramento de Ataques",
  description: "Plataforma de monitoramento de ataques cibernéticos em tempo real",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}
