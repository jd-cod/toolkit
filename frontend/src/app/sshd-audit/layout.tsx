import { createToolLayout } from '@/lib/tool-layout';

const { generateMetadata, Layout } = createToolLayout('sshd-audit');

export { generateMetadata };
export default Layout;
