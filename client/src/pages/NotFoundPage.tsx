import { Compass } from 'lucide-react';
import { Link } from 'react-router';
import { EmptyState } from '../components/ui/States';

export default function NotFoundPage() {
  return (
    <EmptyState
      icon={Compass}
      title="Page not found"
      description="This page does not exist. It may have been moved, or the link is wrong."
      action={
        <Link to="/dashboard" className="text-sm font-medium text-accent hover:underline">
          Back to the dashboard
        </Link>
      }
      className="py-24"
    />
  );
}
