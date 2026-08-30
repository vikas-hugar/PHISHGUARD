import React from 'react';
import { motion } from 'framer-motion';

const techStack = [
    { name: 'Python', category: 'Backend / ML', logo: 'https://cdn.jsdelivr.net/gh/devicons/devicon/icons/python/python-original.svg', color: '#3B82F6' },
    { name: 'PyTorch', category: 'Deep Learning', logo: 'https://cdn.jsdelivr.net/gh/devicons/devicon/icons/pytorch/pytorch-original.svg', color: '#EE4C2C' },
    { name: 'Transformers', category: 'Hugging Face', logo: 'https://huggingface.co/front/assets/huggingface_logo-noborder.svg', color: '#FFD21E' },
    { name: 'RoBERTa', category: 'Transformer NLP', logo: 'https://huggingface.co/front/assets/huggingface_logo-noborder.svg', color: '#FACC15' },
    { name: 'TensorFlow', category: 'Deep Learning', logo: 'https://cdn.jsdelivr.net/gh/devicons/devicon/icons/tensorflow/tensorflow-original.svg', color: '#FF6B35' },
    { name: 'Keras', category: 'Neural Networks', logo: 'https://upload.wikimedia.org/wikipedia/commons/a/ae/Keras_logo.svg', color: '#FF3B3B' },
    { name: 'Flask', category: 'API Server', logo: 'https://cdn.jsdelivr.net/gh/devicons/devicon/icons/flask/flask-original.svg', color: '#9CA3AF', invert: true },
    { name: 'React', category: 'Frontend UI', logo: 'https://cdn.jsdelivr.net/gh/devicons/devicon/icons/react/react-original.svg', color: '#00AEEF' },
    { name: 'Tailwind CSS', category: 'Styling', logo: 'https://upload.wikimedia.org/wikipedia/commons/d/d5/Tailwind_CSS_Logo.svg', color: '#38BDF8' },
    { name: 'Recharts', category: 'Data Viz', logo: 'https://camo.githubusercontent.com/1cb6fc5e4a48c37a61fb5a51e0d3e1e6cda1516cd793e0cf14f34e4d069b9700/68747470733a2f2f7265636861727473732e636f6d2f696d616765732f6c6f676f2e706e67', color: '#7C3AED' },
    { name: 'Pandas', category: 'Data Processing', logo: 'https://cdn.jsdelivr.net/gh/devicons/devicon/icons/pandas/pandas-original.svg', color: '#A78BFA' },
];

const TechStackSection: React.FC = () => {
    return (
        <section className="py-24 relative overflow-hidden"
            style={{ borderTop: '1px solid rgba(255,255,255,0.05)', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <div className="absolute inset-0 bg-dots opacity-15 pointer-events-none" />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center relative z-10">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="mb-14"
                >
                    <div className="section-label mb-5 mx-auto">Built With</div>
                    <h2 className="text-3xl md:text-4xl font-bold text-white mb-3">
                        Technology <span className="text-gradient-blue">Stack</span>
                    </h2>
                    <p className="text-gray-500 text-base max-w-xl mx-auto">
                        Industry-standard tools and frameworks for a production-grade cybersecurity application.
                    </p>
                </motion.div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {techStack.map((tech, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, scale: 0.88 }}
                            whileInView={{ opacity: 1, scale: 1 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.05 }}
                            whileHover={{ y: -5, borderColor: `${tech.color}50` }}
                            className="p-6 rounded-2xl flex flex-col items-center gap-4 cursor-default transition-all duration-300 group"
                            style={{
                                background: 'rgba(255,255,255,0.03)',
                                border: '1px solid rgba(255,255,255,0.07)',
                            }}
                        >
                            <div className="w-14 h-14 rounded-2xl flex items-center justify-center p-2.5 transition-all duration-300"
                                style={{ background: `${tech.color}12`, border: `1px solid ${tech.color}25` }}>
                                <img
                                    src={tech.logo}
                                    alt={tech.name}
                                    className={`w-full h-full object-contain ${tech.invert ? 'invert opacity-70' : ''}`}
                                    onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }}
                                />
                            </div>
                            <div>
                                <h4 className="text-white font-bold text-sm transition-colors duration-200 group-hover:text-primary">{tech.name}</h4>
                                <p className="text-xs text-gray-600 mt-0.5">{tech.category}</p>
                            </div>
                        </motion.div>
                    ))}
                </div>
            </div>
        </section>
    );
};

export default TechStackSection;
