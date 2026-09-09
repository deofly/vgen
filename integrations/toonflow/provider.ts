/** Direct VGen CLI provider metadata for Toonflow. */
declare const exports: any;

const vendor = {
  id: "vgen",
  version: "2.1",
  name: "VGen 本地生成",
  author: "VGen Contributors",
  description: "直接使用本机已登录的 VGen CLI，无需连接地址或密钥。首版提供 39 帧短视频预览；文字和图片服务请继续使用其他供应商。",
  inputs: [],
  inputValues: {},
  models: [{
    name: "MiniMax H3 · 39 帧预览",
    modelName: "h3-8step",
    type: "video",
    mode: ["text", "singleImage", "startEndRequired", "endFrameOptional"],
    audio: true,
    durationResolutionMap: [{ duration: [1.625], resolution: ["768p"] }],
  }],
};

// The trusted AiVideo backend intercepts this provider before sandbox execution.
function videoRequest() { throw new Error("请安装 Toonflow 的 VGen 直接调用集成。"); }
function unsupported() { throw new Error("VGen 当前只提供视频生成，请选择其他文字或图片供应商。"); }
exports.vendor = vendor;
exports.videoRequest = videoRequest;
exports.textRequest = unsupported;
exports.imageRequest = unsupported;
