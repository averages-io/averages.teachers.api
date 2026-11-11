// Averages for Teachers API. Not on the internet by itself: the averages.teachers Worker
// forwards teach.averages.io/api/* here through a service binding, so pages and API share
// one origin and the session cookie stays host-only.
// Only handlers and Durable Object classes may be exported from this file.

import { app } from "./app.ts";

export { TeacherStore } from "./teacherStore.ts";
export default app;
