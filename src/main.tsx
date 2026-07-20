import { Component, type ErrorInfo, type ReactNode, StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

class RootErrorBoundary extends Component<{ children: ReactNode }, { error?: Error }> {
  state: { error?: Error } = {};

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("route-assistant render failed", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <main style={{ padding: 24, fontFamily: "Segoe UI, sans-serif", color: "#24352f" }}>
          <h1 style={{ fontSize: 20 }}>界面渲染出错</h1>
          <p style={{ color: "#6b7c75", lineHeight: 1.6 }}>
            页面发生未捕获错误，通常是前后端数据结构不一致。请重新连接软路由，或重启应用后再试。
          </p>
          <pre style={{ whiteSpace: "pre-wrap", background: "#f4f7f5", padding: 12, borderRadius: 8 }}>
            {this.state.error.message}
          </pre>
          <button type="button" onClick={() => window.location.reload()} style={{ marginTop: 12 }}>
            重新加载
          </button>
        </main>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RootErrorBoundary>
      <App />
    </RootErrorBoundary>
  </StrictMode>,
);

