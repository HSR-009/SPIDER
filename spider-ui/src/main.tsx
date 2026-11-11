import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import App from './app/App';
import './styles/tokens.css';
import './styles/workbench.css';
import './styles/layout.css';
import './styles/experience.css';
import './styles/additions.css';
import './styles/elevation.css';

/** Hosted preview builds use in-memory routing; the normal build keeps real URLs. */
const Router = (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_STANDALONE ? MemoryRouter : BrowserRouter;
const root = document.getElementById('root');
if (!root) throw new Error('Workbench root is unavailable.');
ReactDOM.createRoot(root).render(<React.StrictMode><Router><App /></Router></React.StrictMode>);
