
#include <dotneato.h>
/* Thread safety? */

void quartz_reset(void);
void quartz_begin_job_for_pdf(FILE* ofp, graph_t* g, char** lib, char* user, char* info[], point pages);
void quartz_end_job_for_pdf(void);
void quartz_end_job_for_bitmap(void);
void quartz_begin_graph_for_paged_pdf(GVC_t *gvc, graph_t* g, box bb, point pb);
void quartz_begin_graph_for_embedded_pdf(GVC_t *gvc, graph_t* g, box bb, point pb);
void quartz_begin_graph_for_bitmap(GVC_t *gvc, graph_t* g, box bb, point pb);
void quartz_end_graph(void);
void quartz_begin_page_for_paged_pdf(graph_t* g, point page, double scale, int rot, point offset);
void quartz_begin_page_for_embedded_pdf(graph_t* g, point page, double scale, int rot, point offset);
void quartz_begin_page_for_bitmap(graph_t* g, point page, double scale, int rot, point offset);
void quartz_end_page_for_pdf(void);
void quartz_end_page_for_bitmap(void);
void quartz_begin_node(node_t* n);
void quartz_end_node();
void quartz_begin_context(void);
void quartz_end_context(void);
void quartz_set_font(char* fontname, double fontsize);
void quartz_textline(point p, textline_t* str);
void quartz_set_pencolor(char *name);
void quartz_set_fillcolor(char* name);
void quartz_set_style(char** s);
void quartz_ellipse(point p, int rx, int ry, int filled);
void quartz_polygon(point* A, int n, int filled);
void quartz_beziercurve(point* A, int n, int arrow_at_start, int arrow_at_end);
void quartz_polyline(point* A,int n);
void quartz_user_shape(char *name, point *A, int n, int filled);
point quartz_image_size(graph_t *g, char *shapeimagefile);
point quartz_user_shape_size(node_t *n, char *shapeimagefile);

codegen_t QPDF_CodeGen = {
    quartz_reset,
    quartz_begin_job_for_pdf,
    NULL, /*/ quartz_end_job_for_pdf, */
    quartz_begin_graph_for_paged_pdf,
    quartz_end_graph,
    quartz_begin_page_for_paged_pdf,
    quartz_end_page_for_pdf,
    NULL, /* begin_layer */
    NULL, /* end_layer */
    NULL, /* begin_cluster */
    NULL, /* end_cluster */
    NULL, /* begin_nodes */
    NULL, /* end_nodes */ 
    NULL, /* begin_edges */
    NULL, /* end_edges */ 
    quartz_begin_node,
    quartz_end_node,
    NULL, /* begin_edge */
    NULL, /* end_edge */
    quartz_begin_context,
    quartz_end_context,
	NULL, /* begin_anchor */
	NULL, /* end_anchor */
    quartz_set_font,
    quartz_textline,
    quartz_set_pencolor,
    quartz_set_fillcolor,
    quartz_set_style,
    quartz_ellipse,
    quartz_polygon,
    quartz_beziercurve,
    quartz_polyline,
    FALSE, /* bezier_has_arrows */
    NULL, /* comment */
    NULL, // quartz_textsize,
    NULL, //quartz_user_shape,
    NULL, /* usershapesize */
};
