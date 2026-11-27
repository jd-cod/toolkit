import { createToolLayout } from '@/lib/tool-layout';

const { generateMetadata, Layout } = createToolLayout('systemd-timer');

export { generateMetadata };
export default Layout;
