/** Security sink model for HTMLResponse.content in the Starlette framework. */
import python
import semmle.python.ApiGraphs
import semmle.python.security.dataflow.ReflectedXSSCustomizations

/** The content argument rendered by Starlette's HTMLResponse as an HTML page. */
class StarletteHTMLResponseContentSink extends ReflectedXss::Sink {
  StarletteHTMLResponseContentSink() {
    exists(API::CallNode responseCall |
      responseCall =
        API::moduleImport("starlette").getMember("responses").getMember("HTMLResponse").getACall() and
      this = responseCall.getParameter(0, "content").asSink()
    )
  }
}
